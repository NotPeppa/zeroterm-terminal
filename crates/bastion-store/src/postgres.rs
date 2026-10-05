use bastion_domain::*;
use bastion_secrets::{hash, matches_hash, CipherContext, Credential, Envelope, KeyRing, Secret};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgRow},
    ConnectOptions, Connection as _, Executor, PgConnection, PgPool, Postgres, Row, Transaction,
};
use std::{str::FromStr, sync::Arc, time::Duration};
use uuid::Uuid;

pub type StoreResult<T> = Result<T, ErrorCode>;
pub(super) fn db(error: sqlx::Error) -> ErrorCode {
    if let sqlx::Error::Database(ref detail) = error {
        if detail.is_unique_violation() {
            return ErrorCode::ResourceConflict;
        }
        if detail.is_foreign_key_violation() || detail.is_check_violation() {
            return ErrorCode::InvalidArgument;
        }
    }
    let error_kind = match &error {
        sqlx::Error::Database(detail) => {
            tracing::warn!(
                sqlstate = detail.code().as_deref().unwrap_or("unknown"),
                "policy database query failed"
            );
            "database"
        }
        sqlx::Error::PoolTimedOut => "pool_timeout",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::RowNotFound => "row_not_found",
        _ => "other",
    };
    tracing::warn!(error_kind, "policy database operation failed");
    ErrorCode::PolicyStoreUnavailable
}
pub async fn bounded<T>(
    future: impl std::future::Future<Output = StoreResult<T>>,
) -> StoreResult<T> {
    tokio::time::timeout(Duration::from_secs(2), future)
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(budget_ms = 2000, "policy transaction total budget elapsed");
            Err(ErrorCode::PolicyStoreUnavailable)
        })
}
#[derive(Clone)]
pub struct PgStore {
    pub pool: PgPool,
    pub server_id: Arc<str>,
    pub gateway_id: Arc<str>,
}
impl PgStore {
    pub async fn connect(url: &str, server_id: &str, gateway_id: &str) -> StoreResult<Self> {
        let options = PgConnectOptions::from_str(url)
            .map_err(db)?
            .disable_statement_logging();
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .acquire_timeout(Duration::from_secs(2))
            .after_connect(|connection, _| {
                Box::pin(async move {
                    connection
                        .execute("SET statement_timeout='2s'; SET lock_timeout='2s'")
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .map_err(db)?;
        Ok(Self {
            pool,
            server_id: server_id.into(),
            gateway_id: gateway_id.into(),
        })
    }
    pub async fn migrate(&self) -> StoreResult<()> {
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|_| ErrorCode::PolicyStoreUnavailable)?;
        sqlx::query("INSERT INTO server_settings(singleton,server_id) VALUES(true,$1) ON CONFLICT DO NOTHING").bind(self.server_id.as_ref()).execute(&self.pool).await.map_err(db)?;
        self.check_identity().await
    }
    pub async fn check_identity(&self) -> StoreResult<()> {
        let id: String = sqlx::query_scalar(
            "SELECT server_id FROM server_settings WHERE singleton AND schema_version=1",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        if id != self.server_id.as_ref() {
            return Err(ErrorCode::ResourceConflict);
        }
        Ok(())
    }
    pub async fn gateway_lock(&self) -> StoreResult<PgConnection> {
        let mut connection = PgConnection::connect_with(&self.pool.connect_options())
            .await
            .map_err(db)?;
        let key = format!("zeroterm-bastion:{}:{}", self.server_id, self.gateway_id);
        let locked: bool =
            sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1,0))")
                .bind(key)
                .fetch_one(&mut connection)
                .await
                .map_err(db)?;
        if !locked {
            return Err(ErrorCode::ResourceConflict);
        }
        Ok(connection)
    }
    pub(super) async fn begin(&self) -> StoreResult<Transaction<'_, Postgres>> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT policy_revision FROM server_settings WHERE singleton FOR UPDATE")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        Ok(tx)
    }
    pub async fn policy_revision(&self) -> StoreResult<i64> {
        sqlx::query_scalar("SELECT policy_revision FROM server_settings WHERE singleton")
            .fetch_one(&self.pool)
            .await
            .map_err(db)
    }
    pub async fn bootstrap_admin(
        &self,
        username: &str,
        password_hash: &str,
        request_id: Uuid,
    ) -> StoreResult<UserView> {
        bounded(async {
            let mut tx = self.begin().await?;
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE role='admin'")
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
            if count != 0 {
                return Err(ErrorCode::ResourceConflict);
            }
            let user = insert_user(&mut tx, username, password_hash, Role::Admin).await?;
            audit(
                &mut tx,
                Some(user.id),
                None,
                "user.bootstrap",
                "user",
                Some(user.id),
                request_id,
                json!({"username":user.username}),
            )
            .await?;
            tx.commit().await.map_err(db)?;
            Ok(user)
        })
        .await
    }
    pub async fn login_candidate(&self, username: &str) -> StoreResult<Option<(UserView, String)>> {
        let row = sqlx::query("SELECT * FROM users WHERE username=$1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| Ok((user_view(&r)?, r.get("password_hash"))))
            .transpose()
    }
    pub async fn login(
        &self,
        verified: &UserView,
        verified_hash: &str,
        label: &str,
        request_id: Uuid,
    ) -> StoreResult<LoginResponse> {
        self.login_inner(verified, verified_hash, label, request_id, "zeroterm")
            .await
    }
    pub async fn login_web(
        &self,
        verified: &UserView,
        verified_hash: &str,
        label: &str,
        request_id: Uuid,
    ) -> StoreResult<LoginResponse> {
        self.login_inner(verified, verified_hash, label, request_id, "web")
            .await
    }
    async fn login_inner(
        &self,
        verified: &UserView,
        verified_hash: &str,
        label: &str,
        request_id: Uuid,
        client_type: &str,
    ) -> StoreResult<LoginResponse> {
        bounded(async {
            let mut tx=self.begin().await?;
            let row=sqlx::query("SELECT * FROM users WHERE id=$1 FOR UPDATE").bind(verified.id).fetch_one(&mut *tx).await.map_err(db)?;
            let user=user_view(&row)?;
            if !user.enabled || user.revision!=verified.revision || row.get::<String,_>("password_hash")!=verified_hash {return Err(ErrorCode::Unauthenticated); }
            let access=Secret::random();let refresh=Secret::random();let session=Uuid::new_v4();
            let expiry:DateTime<Utc>=sqlx::query_scalar("INSERT INTO login_sessions(id,user_id,device_label,family_id,refresh_hash,expires_at,client_type) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '7 days',$6) RETURNING expires_at")
                .bind(session).bind(user.id).bind(label).bind(Uuid::new_v4()).bind(refresh.hash().as_slice()).bind(client_type).fetch_one(&mut *tx).await.map_err(db)?;
            let access_expiry=insert_tokens(&mut tx,session,&access,&refresh,expiry).await?;
            audit(&mut tx,Some(user.id),Some(session),"user.login_success","login_session",Some(session),request_id,json!({"device_label":label})).await?;
            tx.commit().await.map_err(db)?;
            Ok(LoginResponse {user,access_token:access.expose().into(),refresh_token:refresh.expose().into(),login_session_id:session,access_expires_at:access_expiry,refresh_expires_at:expiry})
        }).await
    }
    pub async fn login_failure(&self, request_id: Uuid) -> StoreResult<()> {
        let mut tx = self.begin().await?;
        audit(
            &mut tx,
            None,
            None,
            "user.login_failure",
            "user",
            None,
            request_id,
            json!({"reason_code":"UNAUTHENTICATED"}),
        )
        .await?;
        tx.commit().await.map_err(db)
    }
    pub async fn authenticate(&self, secret: &str) -> StoreResult<Identity> {
        self.authenticate_inner(secret, "zeroterm").await
    }
    pub async fn authenticate_web(&self, secret: &str) -> StoreResult<Identity> {
        self.authenticate_inner(secret, "web").await
    }
    async fn authenticate_inner(&self, secret: &str, client_type: &str) -> StoreResult<Identity> {
        let row=sqlx::query("SELECT u.*,s.id AS session_id,s.revoked_at,s.expires_at>clock_timestamp() AS session_valid,t.expires_at>clock_timestamp() AS token_valid FROM access_tokens t JOIN login_sessions s ON s.id=t.login_session_id JOIN users u ON u.id=s.user_id WHERE t.token_hash=$1 AND s.client_type=$2")
            .bind(hash(secret).as_slice()).bind(client_type).fetch_optional(&self.pool).await.map_err(db)?.ok_or(ErrorCode::Unauthenticated)?;
        identity_from_row(&row)
    }
    pub(super) async fn actor(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        identity: &Identity,
        admin: bool,
    ) -> StoreResult<()> {
        let row=sqlx::query("SELECT u.*,s.id AS session_id,s.revoked_at,s.expires_at>clock_timestamp() AS session_valid,true AS token_valid FROM users u JOIN login_sessions s ON s.user_id=u.id WHERE u.id=$1 AND s.id=$2 FOR UPDATE OF u,s")
            .bind(identity.user.id).bind(identity.login_session_id).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(ErrorCode::Unauthenticated)?;
        let current = identity_from_row(&row)?;
        if current.user.revision != identity.user.revision {
            return Err(ErrorCode::LoginSessionRevoked);
        }
        if admin && current.user.role != Role::Admin {
            return Err(ErrorCode::PermissionDenied);
        }
        Ok(())
    }
    pub async fn refresh(&self, secret: &str, request_id: Uuid) -> StoreResult<LoginResponse> {
        self.refresh_inner(secret, request_id, "zeroterm").await
    }
    pub async fn refresh_web(&self, secret: &str, request_id: Uuid) -> StoreResult<LoginResponse> {
        self.refresh_inner(secret, request_id, "web").await
    }
    async fn refresh_inner(
        &self,
        secret: &str,
        request_id: Uuid,
        client_type: &str,
    ) -> StoreResult<LoginResponse> {
        bounded(async {
            // Policy lock precedes identity/token locks, including replay revocation.
            let mut tx=self.begin().await?;
            let row=sqlx::query("SELECT r.id AS refresh_id,r.state,r.expires_at>clock_timestamp() AS refresh_valid,u.*,s.id AS session_id,s.revoked_at,s.expires_at AS family_expiry,s.expires_at>clock_timestamp() AS session_valid,true AS token_valid FROM refresh_tokens r JOIN login_sessions s ON s.id=r.login_session_id JOIN users u ON u.id=s.user_id WHERE r.token_hash=$1 AND s.client_type=$2 FOR UPDATE OF u,s,r")
                .bind(hash(secret).as_slice()).bind(client_type).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::Unauthenticated)?;
            let session:Uuid=row.get("session_id");let uid:Uuid=row.get("id");
            if row.get::<String,_>("state")!="active" {
                revoke_session(&mut tx,session).await?;
                audit(&mut tx,Some(uid),Some(session),"user.refresh_replay","login_session",Some(session),request_id,json!({})).await?;
                tx.commit().await.map_err(db)?;return Err(ErrorCode::LoginSessionRevoked);
            }
            let identity=identity_from_row(&row)?;
            if !row.get::<bool,_>("refresh_valid") {return Err(ErrorCode::Unauthenticated); }
            let access=Secret::random();let refresh=Secret::random();let new_id=Uuid::new_v4();let expiry=row.get("family_expiry");
            let access_expiry=insert_tokens_with_id(&mut tx,session,new_id,&access,&refresh,expiry).await?;
            sqlx::query("UPDATE refresh_tokens SET state='rotated',rotated_at=clock_timestamp(),replaced_by=$2 WHERE id=$1").bind(row.get::<Uuid,_>("refresh_id")).bind(new_id).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("UPDATE login_sessions SET refresh_hash=$2 WHERE id=$1").bind(session).bind(refresh.hash().as_slice()).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx,Some(uid),Some(session),"user.refresh","login_session",Some(session),request_id,json!({})).await?;
            tx.commit().await.map_err(db)?;
            Ok(LoginResponse {user:identity.user,access_token:access.expose().into(),refresh_token:refresh.expose().into(),login_session_id:session,access_expires_at:access_expiry,refresh_expires_at:expiry})
        }).await
    }
    pub async fn logout(
        &self,
        identity: &Identity,
        all: bool,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, identity, false).await?;
            if all {
                revoke_user(&mut tx, identity.user.id).await?;
            } else {
                revoke_session(&mut tx, identity.login_session_id).await?;
            }
            audit(
                &mut tx,
                Some(identity.user.id),
                Some(identity.login_session_id),
                if all {
                    "user.logout_all"
                } else {
                    "user.logout"
                },
                "user",
                Some(identity.user.id),
                request_id,
                json!({}),
            )
            .await?;
            tx.commit().await.map_err(db)
        })
        .await
    }
}

#[derive(Clone, Serialize)]
pub struct AssetView {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: i32,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub revision: i64,
    pub routing_revision: i64,
}
#[derive(Clone, Serialize)]
pub struct AccountView {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub username: String,
    pub enabled: bool,
    pub revision: i64,
    pub credential_kind: String,
    pub credential_revision: i64,
}
#[derive(Clone, Serialize)]
pub struct GrantView {
    pub id: Uuid,
    pub user_id: Uuid,
    pub asset_id: Uuid,
    pub account_id: Uuid,
    pub capabilities: Vec<Capability>,
    pub enabled: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub revision: i64,
}
#[derive(Clone, Serialize)]
pub struct HostKeyView {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub state: String,
    pub revision: i64,
}
pub struct TargetSnapshot {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub keys: Vec<String>,
    pub credential: Envelope,
    pub context: CipherContext,
}

impl PgStore {
    pub async fn create_user(
        &self,
        actor: &Identity,
        username: &str,
        password_hash: &str,
        role: Role,
        request_id: Uuid,
    ) -> StoreResult<UserView> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, actor, true).await?;
            let user = insert_user(&mut tx, username, password_hash, role).await?;
            audit(
                &mut tx,
                Some(actor.user.id),
                Some(actor.login_session_id),
                "user.created",
                "user",
                Some(user.id),
                request_id,
                json!({"username":username,"role":role}),
            )
            .await?;
            tx.commit().await.map_err(db)?;
            Ok(user)
        })
        .await
    }
    pub async fn users(&self) -> StoreResult<Vec<UserView>> {
        sqlx::query("SELECT id,username,role,enabled,auth_revision FROM users ORDER BY created_at,id LIMIT 200").fetch_all(&self.pool).await.map_err(db)?.iter().map(user_view).collect()
    }
    pub async fn update_user(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        role: Option<Role>,
        enabled: Option<bool>,
        request_id: Uuid,
    ) -> StoreResult<UserView> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            let row=sqlx::query("UPDATE users SET role=COALESCE($3,role),enabled=COALESCE($4,enabled),auth_revision=auth_revision+1 WHERE id=$1 AND auth_revision=$2 RETURNING *")
                .bind(id).bind(revision).bind(role.map(Role::as_str)).bind(enabled).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::RevisionConflict)?;
            revoke_user(&mut tx,id).await?;
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"user.updated","user",Some(id),request_id,json!({"role":role,"enabled":enabled})).await?;
            tx.commit().await.map_err(db)?;user_view(&row)
        }).await
    }
    pub async fn reset_password(
        &self,
        actor: Option<&Identity>,
        id: Uuid,
        revision: i64,
        phc: &str,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;
            if let Some(actor)=actor { self.actor(&mut tx,actor,true).await?; }
            let changed=sqlx::query("UPDATE users SET password_hash=$3,enabled=true,auth_revision=auth_revision+1 WHERE id=$1 AND auth_revision=$2").bind(id).bind(revision).bind(phc).execute(&mut *tx).await.map_err(db)?;
            if changed.rows_affected()!=1 {return Err(ErrorCode::RevisionConflict); }
            revoke_user(&mut tx,id).await?;
            audit(&mut tx,actor.map(|a|a.user.id),actor.map(|a|a.login_session_id),"user.password_reset","user",Some(id),request_id,json!({"via_cli":actor.is_none()})).await?;
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn change_password(
        &self,
        actor: &Identity,
        previous_phc: &str,
        new_phc: &str,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,false).await?;
            let updated=sqlx::query("UPDATE users SET password_hash=$2,auth_revision=auth_revision+1 WHERE id=$1 AND password_hash=$3").bind(actor.user.id).bind(new_phc).bind(previous_phc).execute(&mut *tx).await.map_err(db)?;
            if updated.rows_affected()!=1 {return Err(ErrorCode::RevisionConflict); }
            revoke_user(&mut tx,actor.user.id).await?;
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"user.password_changed","user",Some(actor.user.id),request_id,json!({})).await?;
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn create_asset(
        &self,
        actor: &Identity,
        name: &str,
        host: &str,
        port: u16,
        tags: &[String],
        request_id: Uuid,
    ) -> StoreResult<AssetView> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, actor, true).await?;
            let row = sqlx::query(
                "INSERT INTO assets(id,name,host,port,tags) VALUES($1,$2,$3,$4,$5) RETURNING *",
            )
            .bind(Uuid::new_v4())
            .bind(name)
            .bind(host)
            .bind(i32::from(port))
            .bind(tags)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            let asset = asset_view(&row);
            audit(
                &mut tx,
                Some(actor.user.id),
                Some(actor.login_session_id),
                "asset.created",
                "asset",
                Some(asset.id),
                request_id,
                json!({"name":name,"host":host,"port":port}),
            )
            .await?;
            tx.commit().await.map_err(db)?;
            Ok(asset)
        })
        .await
    }
    pub async fn admin_assets(&self) -> StoreResult<Vec<AssetView>> {
        Ok(
            sqlx::query("SELECT * FROM assets ORDER BY created_at,id LIMIT 200")
                .fetch_all(&self.pool)
                .await
                .map_err(db)?
                .iter()
                .map(asset_view)
                .collect(),
        )
    }
    pub async fn asset(&self, id: Uuid) -> StoreResult<AssetView> {
        sqlx::query("SELECT * FROM assets WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .map(|r| asset_view(&r))
            .ok_or(ErrorCode::ResourceNotFound)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn update_asset(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        name: Option<&str>,
        host: Option<&str>,
        port: Option<u16>,
        enabled: Option<bool>,
        tags: Option<&[String]>,
        request_id: Uuid,
    ) -> StoreResult<AssetView> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            let before=sqlx::query("SELECT host,port,enabled FROM assets WHERE id=$1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            let route_changed=host.is_some_and(|v|v!=before.get::<String,_>("host")) || port.is_some_and(|v|i32::from(v)!=before.get::<i32,_>("port")) || enabled.is_some_and(|v|v!=before.get::<bool,_>("enabled"));
            let row=sqlx::query("UPDATE assets SET name=COALESCE($3,name),host=COALESCE($4,host),port=COALESCE($5,port),enabled=COALESCE($6,enabled),tags=COALESCE($7,tags),config_revision=config_revision+1,routing_revision=routing_revision+CASE WHEN $8 THEN 1 ELSE 0 END WHERE id=$1 AND config_revision=$2 RETURNING *")
                .bind(id).bind(revision).bind(name).bind(host).bind(port.map(i32::from)).bind(enabled).bind(tags).bind(route_changed).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::RevisionConflict)?;
            if route_changed {invalidate_asset(&mut tx,id).await?;}
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"asset.updated","asset",Some(id),request_id,json!({"host":host,"port":port,"enabled":enabled})).await?;
            tx.commit().await.map_err(db)?;Ok(asset_view(&row))
        }).await
    }
    pub async fn create_account(
        &self,
        actor: &Identity,
        asset: Uuid,
        username: &str,
        credential: &Credential,
        keys: &KeyRing,
        request_id: Uuid,
    ) -> StoreResult<AccountView> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            sqlx::query("SELECT id FROM assets WHERE id=$1 FOR UPDATE").bind(asset).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            let credential_id=Uuid::new_v4();let context=CipherContext {server_id:self.server_id.to_string(),credential_id,kind:credential.kind().into(),revision:1};
            let encrypted=keys.seal(&context,credential).map_err(|_|ErrorCode::InternalError)?;
            sqlx::query("INSERT INTO credentials(id,kind,revision,ciphertext,nonce,wrapped_dek,wrap_nonce,key_version) VALUES($1,$2,1,$3,$4,$5,$6,$7)")
                .bind(credential_id).bind(credential.kind()).bind(&encrypted.ciphertext).bind(&encrypted.nonce).bind(&encrypted.wrapped_dek).bind(&encrypted.wrap_nonce).bind(encrypted.key_version).execute(&mut *tx).await.map_err(db)?;
            let id=Uuid::new_v4();
            sqlx::query("INSERT INTO target_accounts(id,asset_id,username,credential_id) VALUES($1,$2,$3,$4)").bind(id).bind(asset).bind(username).bind(credential_id).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"credential.created","account",Some(id),request_id,json!({"asset_id":asset,"username":username,"kind":credential.kind()})).await?;
            tx.commit().await.map_err(db)?;self.account(id).await
        }).await
    }
    pub async fn account(&self, id: Uuid) -> StoreResult<AccountView> {
        let row=sqlx::query("SELECT a.*,c.kind,c.revision AS credential_revision FROM target_accounts a JOIN credentials c ON c.id=a.credential_id WHERE a.id=$1").bind(id).fetch_optional(&self.pool).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
        Ok(account_view(&row))
    }
    pub async fn accounts(&self, asset: Uuid) -> StoreResult<Vec<AccountView>> {
        Ok(sqlx::query("SELECT a.*,c.kind,c.revision AS credential_revision FROM target_accounts a JOIN credentials c ON c.id=a.credential_id WHERE a.asset_id=$1 ORDER BY a.id LIMIT 200").bind(asset).fetch_all(&self.pool).await.map_err(db)?.iter().map(account_view).collect())
    }
    pub async fn replace_credential(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        credential: &Credential,
        keys: &KeyRing,
        request_id: Uuid,
    ) -> StoreResult<AccountView> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            let row=sqlx::query("SELECT a.credential_id,a.config_revision,c.revision FROM target_accounts a JOIN assets s ON s.id=a.asset_id JOIN credentials c ON c.id=a.credential_id WHERE a.id=$1 FOR UPDATE OF s,a,c").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            if row.get::<i64,_>("config_revision")!=revision {return Err(ErrorCode::RevisionConflict); }
            let credential_id=row.get("credential_id");let next=row.get::<i64,_>("revision")+1;
            let context=CipherContext {server_id:self.server_id.to_string(),credential_id,kind:credential.kind().into(),revision:next};let encrypted=keys.seal(&context,credential).map_err(|_|ErrorCode::InternalError)?;
            sqlx::query("UPDATE credentials SET kind=$2,revision=$3,ciphertext=$4,nonce=$5,wrapped_dek=$6,wrap_nonce=$7,key_version=$8 WHERE id=$1")
                .bind(credential_id).bind(credential.kind()).bind(next).bind(encrypted.ciphertext).bind(encrypted.nonce).bind(encrypted.wrapped_dek).bind(encrypted.wrap_nonce).bind(encrypted.key_version).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("UPDATE target_accounts SET config_revision=config_revision+1 WHERE id=$1").bind(id).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"credential.replaced","account",Some(id),request_id,json!({"kind":credential.kind(),"revision":next})).await?;
            tx.commit().await.map_err(db)?;self.account(id).await
        }).await
    }
    pub async fn update_account(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        enabled: Option<bool>,
        username: Option<&str>,
        request_id: Uuid,
    ) -> StoreResult<AccountView> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            let changed=sqlx::query("UPDATE target_accounts SET enabled=COALESCE($3,enabled),username=COALESCE($4,username),config_revision=config_revision+1 WHERE id=$1 AND config_revision=$2").bind(id).bind(revision).bind(enabled).bind(username).execute(&mut *tx).await.map_err(db)?;
            if changed.rows_affected()!=1 {return Err(ErrorCode::RevisionConflict); }
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"account.updated","account",Some(id),request_id,json!({"enabled":enabled,"username":username})).await?;
            tx.commit().await.map_err(db)?;self.account(id).await
        }).await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn save_host_key(
        &self,
        actor: &Identity,
        asset: Uuid,
        algorithm: &str,
        public_key: &str,
        fingerprint: &str,
        approved: bool,
        request_id: Uuid,
    ) -> StoreResult<HostKeyView> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            sqlx::query("SELECT id FROM assets WHERE id=$1 FOR UPDATE").bind(asset).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            let row=sqlx::query("INSERT INTO asset_host_keys(id,asset_id,algorithm,public_key,fingerprint,state,approved_by) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(asset_id,public_key) DO UPDATE SET state=CASE WHEN EXCLUDED.state='approved' THEN 'approved' ELSE asset_host_keys.state END,approved_by=CASE WHEN EXCLUDED.state='approved' THEN EXCLUDED.approved_by ELSE asset_host_keys.approved_by END,revision=asset_host_keys.revision+CASE WHEN EXCLUDED.state='approved' THEN 1 ELSE 0 END RETURNING *")
                .bind(Uuid::new_v4()).bind(asset).bind(algorithm).bind(public_key).bind(fingerprint).bind(if approved{"approved"}else{"candidate"}).bind(if approved{Some(actor.user.id)}else{None}).fetch_one(&mut *tx).await.map_err(db)?;
            if approved { sqlx::query("UPDATE assets SET config_revision=config_revision+1,routing_revision=routing_revision+1 WHERE id=$1").bind(asset).execute(&mut *tx).await.map_err(db)?; }
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),if approved{"host_key.approved"}else{"host_key.scanned"},"asset",Some(asset),request_id,json!({"fingerprint":fingerprint})).await?;
            tx.commit().await.map_err(db)?;Ok(host_key_view(&row))
        }).await
    }
    pub async fn host_keys(&self, asset: Uuid) -> StoreResult<Vec<HostKeyView>> {
        Ok(
            sqlx::query("SELECT * FROM asset_host_keys WHERE asset_id=$1 ORDER BY id LIMIT 200")
                .bind(asset)
                .fetch_all(&self.pool)
                .await
                .map_err(db)?
                .iter()
                .map(host_key_view)
                .collect(),
        )
    }
    pub async fn revoke_host_key(
        &self,
        actor: &Identity,
        asset: Uuid,
        id: Uuid,
        revision: i64,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            let changed=sqlx::query("UPDATE asset_host_keys SET state='revoked',revision=revision+1 WHERE id=$1 AND asset_id=$2 AND revision=$3").bind(id).bind(asset).bind(revision).execute(&mut *tx).await.map_err(db)?;
            if changed.rows_affected()!=1 {return Err(ErrorCode::RevisionConflict); }
            sqlx::query("UPDATE assets SET config_revision=config_revision+1,routing_revision=routing_revision+1 WHERE id=$1").bind(asset).execute(&mut *tx).await.map_err(db)?;
            invalidate_asset(&mut tx,asset).await?;
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"host_key.revoked","asset",Some(asset),request_id,json!({"key_id":id})).await?;
            tx.commit().await.map_err(db)
        }).await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn create_grant(
        &self,
        actor: &Identity,
        user: Uuid,
        asset: Uuid,
        account: Uuid,
        capabilities: &[Capability],
        expires: Option<DateTime<Utc>>,
        request_id: Uuid,
    ) -> StoreResult<GrantView> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            let row=sqlx::query("INSERT INTO grants(id,user_id,asset_id,account_id,capabilities,expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING *").bind(Uuid::new_v4()).bind(user).bind(asset).bind(account).bind(cap_strings(capabilities)).bind(expires).fetch_one(&mut *tx).await.map_err(db)?;
            bump_policy(&mut tx).await?;
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"grant.created","grant",Some(row.get("id")),request_id,json!({"user_id":user,"asset_id":asset,"account_id":account,"capabilities":capabilities})).await?;
            tx.commit().await.map_err(db)?;grant_view(&row)
        }).await
    }
    pub async fn grants(&self) -> StoreResult<Vec<GrantView>> {
        sqlx::query("SELECT * FROM grants ORDER BY id LIMIT 200")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?
            .iter()
            .map(grant_view)
            .collect()
    }
    pub async fn revoke_grant(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            let row=sqlx::query("UPDATE grants SET enabled=false,revision=revision+1 WHERE id=$1 AND revision=$2 RETURNING *").bind(id).bind(revision).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::RevisionConflict)?;
            bump_policy(&mut tx).await?;
            invalidate_grant(&mut tx,&row).await?;
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"grant.revoked","grant",Some(id),request_id,json!({"user_id":row.get::<Uuid,_>("user_id")})).await?;
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn assets_for(&self, identity: &Identity) -> StoreResult<Value> {
        if identity.user.role == Role::Auditor {
            return Err(ErrorCode::PermissionDenied);
        }
        let rows=sqlx::query("SELECT a.*,t.id AS account_id,t.username,array_agg(DISTINCT cap ORDER BY cap) AS capabilities FROM assets a JOIN target_accounts t ON t.asset_id=a.id JOIN grants g ON g.asset_id=a.id AND g.account_id=t.id CROSS JOIN LATERAL unnest(g.capabilities) cap WHERE g.user_id=$1 AND g.enabled AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()) AND a.enabled AND t.enabled GROUP BY a.id,t.id ORDER BY a.created_at,a.id,t.id LIMIT 200")
            .bind(identity.user.id).fetch_all(&self.pool).await.map_err(db)?;
        let mut items: Vec<Value> = Vec::new();
        for row in rows {
            let asset: Uuid = row.get("id");
            let account = json!({"id":row.get::<Uuid,_>("account_id"),"username":row.get::<String,_>("username"),"capabilities":row.get::<Vec<String>,_>("capabilities")});
            if let Some(existing) = items.iter_mut().find(|v| v["id"] == json!(asset)) {
                existing["accounts"].as_array_mut().unwrap().push(account);
            } else {
                items.push(json!({"id":asset,"name":row.get::<String,_>("name"),"tags":row.get::<Vec<String>,_>("tags"),"revision":row.get::<i64,_>("config_revision"),"accounts":[account]}));
            }
        }
        Ok(
            json!({"items":items,"next_cursor":null,"policy_revision":self.policy_revision().await?}),
        )
    }
    pub async fn audit_events(&self, identity: &Identity) -> StoreResult<Value> {
        if !matches!(identity.user.role, Role::Admin | Role::Auditor) {
            return Err(ErrorCode::PermissionDenied);
        }
        let values:Vec<Value>=sqlx::query_scalar("SELECT to_jsonb(e) FROM (SELECT * FROM audit_events ORDER BY occurred_at DESC,id DESC LIMIT 200) e").fetch_all(&self.pool).await.map_err(db)?;
        Ok(json!({"items":values,"next_cursor":null}))
    }
}
fn asset_view(row: &PgRow) -> AssetView {
    AssetView {
        id: row.get("id"),
        name: row.get("name"),
        host: row.get("host"),
        port: row.get("port"),
        tags: row.get("tags"),
        enabled: row.get("enabled"),
        revision: row.get("config_revision"),
        routing_revision: row.get("routing_revision"),
    }
}
fn account_view(row: &PgRow) -> AccountView {
    AccountView {
        id: row.get("id"),
        asset_id: row.get("asset_id"),
        username: row.get("username"),
        enabled: row.get("enabled"),
        revision: row.get("config_revision"),
        credential_kind: row.get("kind"),
        credential_revision: row.get("credential_revision"),
    }
}
fn host_key_view(row: &PgRow) -> HostKeyView {
    HostKeyView {
        id: row.get("id"),
        asset_id: row.get("asset_id"),
        algorithm: row.get("algorithm"),
        public_key: row.get("public_key"),
        fingerprint: row.get("fingerprint"),
        state: row.get("state"),
        revision: row.get("revision"),
    }
}
fn grant_view(row: &PgRow) -> StoreResult<GrantView> {
    Ok(GrantView {
        id: row.get("id"),
        user_id: row.get("user_id"),
        asset_id: row.get("asset_id"),
        account_id: row.get("account_id"),
        capabilities: parse_caps(row.get("capabilities"))?,
        enabled: row.get("enabled"),
        expires_at: row.get("expires_at"),
        revision: row.get("revision"),
    })
}
fn cap_strings(capabilities: &[Capability]) -> Vec<&str> {
    capabilities.iter().map(|c| c.as_str()).collect()
}
fn parse_caps(values: Vec<String>) -> StoreResult<Vec<Capability>> {
    values
        .iter()
        .map(|s| match s.as_str() {
            "shell" => Ok(Capability::Shell),
            "exec" => Ok(Capability::Exec),
            "sftp" => Ok(Capability::Sftp),
            _ => Err(ErrorCode::InternalError),
        })
        .collect()
}
async fn bump_policy(tx: &mut Transaction<'_, Postgres>) -> StoreResult<()> {
    sqlx::query("UPDATE server_settings SET policy_revision=policy_revision+1 WHERE singleton")
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
async fn invalidate_asset(tx: &mut Transaction<'_, Postgres>, asset: Uuid) -> StoreResult<()> {
    sqlx::query(
        "UPDATE connection_tickets SET state='revoked' WHERE asset_id=$1 AND state='issued'",
    )
    .bind(asset)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    sqlx::query("UPDATE connections SET state='revoked',ended_at=clock_timestamp() WHERE asset_id=$1 AND state='pending'").bind(asset).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}

pub(super) struct Binding {
    pub(super) user: UserView,
    pub(super) asset: AssetView,
    pub(super) account_revision: i64,
    pub(super) username: String,
    pub(super) capabilities: Vec<Capability>,
}
impl PgStore {
    pub(super) async fn binding(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        user: Uuid,
        session: Uuid,
        asset: Uuid,
        account: Uuid,
    ) -> StoreResult<Binding> {
        let row=sqlx::query("SELECT u.*,s.id AS session_id,s.revoked_at,s.expires_at>clock_timestamp() AS session_valid,true AS token_valid FROM users u JOIN login_sessions s ON s.user_id=u.id WHERE u.id=$1 AND s.id=$2 FOR UPDATE OF u,s")
            .bind(user).bind(session).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(ErrorCode::Unauthenticated)?;
        let identity = identity_from_row(&row)?;
        if identity.user.role == Role::Auditor {
            return Err(ErrorCode::PermissionDenied);
        }
        let row=sqlx::query("SELECT a.*,t.username,t.config_revision AS account_revision,t.enabled AS account_enabled FROM assets a JOIN target_accounts t ON t.asset_id=a.id WHERE a.id=$1 AND t.id=$2 FOR UPDATE OF a,t")
            .bind(asset).bind(account).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(ErrorCode::PermissionDenied)?;
        if !row.get::<bool, _>("enabled") || !row.get::<bool, _>("account_enabled") {
            return Err(ErrorCode::PermissionDenied);
        }
        let caps:Option<Vec<String>>=sqlx::query_scalar("SELECT array_agg(DISTINCT cap ORDER BY cap) FROM grants g CROSS JOIN LATERAL unnest(g.capabilities) cap WHERE g.user_id=$1 AND g.asset_id=$2 AND g.account_id=$3 AND g.enabled AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp())")
            .bind(user).bind(asset).bind(account).fetch_one(&mut **tx).await.map_err(db)?;
        Ok(Binding {
            user: identity.user,
            asset: asset_view(&row),
            account_revision: row.get("account_revision"),
            username: row.get("username"),
            capabilities: parse_caps(caps.unwrap_or_default())?,
        })
    }
    pub async fn issue_ticket(
        &self,
        identity: &Identity,
        request: TicketRequest,
        gateway: GatewayAddress,
        request_id: Uuid,
    ) -> StoreResult<TicketResponse> {
        let session = self
            .issue_session(identity, request, TicketTransport::Ssh, request_id)
            .await?;
        Ok(TicketResponse {
            protocol_version: session.protocol_version,
            ticket_id: session.session_id,
            ticket_secret: session.ws_token,
            connection_id: session.connection_id,
            expires_at: session.expires_at,
            gateway: GatewayAddress {
                username: format!("zt1:{}", session.session_id),
                ..gateway
            },
            capabilities: session.capabilities,
        })
    }
    pub async fn issue_web_session(
        &self,
        identity: &Identity,
        request: TicketRequest,
        request_id: Uuid,
    ) -> StoreResult<WebSessionResponse> {
        self.issue_session(identity, request, TicketTransport::Websocket, request_id)
            .await
    }
    async fn issue_session(
        &self,
        identity: &Identity,
        mut request: TicketRequest,
        transport: TicketTransport,
        request_id: Uuid,
    ) -> StoreResult<WebSessionResponse> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,identity,false).await?;
            expire_tickets(&mut tx).await?;
            let binding=self.binding(&mut tx,identity.user.id,identity.login_session_id,request.asset_id,request.account_id).await?;
            request.validate(&binding.capabilities)?;
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM connection_tickets WHERE user_id=$1 AND state='issued' AND expires_at>clock_timestamp()").bind(identity.user.id).fetch_one(&mut *tx).await.map_err(db)?;
            if count>=20 {return Err(ErrorCode::ConnectionLimit); }
            connection_limits(&mut tx,identity.user.id).await?;
            let policy:i64=sqlx::query_scalar("SELECT policy_revision FROM server_settings WHERE singleton").fetch_one(&mut *tx).await.map_err(db)?;
            let ticket=Uuid::new_v4();let connection=Uuid::new_v4();let secret=Secret::random();
            let expiry:DateTime<Utc>=sqlx::query_scalar("INSERT INTO connection_tickets(id,secret_hash,connection_id,user_id,login_session_id,asset_id,account_id,capabilities,purpose,gateway_id,auth_revision,asset_revision,account_revision,policy_revision,state,expires_at,transport,protocol_version,routing_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'issued',clock_timestamp()+interval '30 seconds',$15,1,$16) RETURNING expires_at")
                .bind(ticket).bind(secret.hash().as_slice()).bind(connection).bind(identity.user.id).bind(identity.login_session_id).bind(request.asset_id).bind(request.account_id).bind(cap_strings(&request.capabilities)).bind(request.purpose.as_str()).bind(self.gateway_id.as_ref()).bind(binding.user.revision).bind(binding.asset.revision).bind(binding.account_revision).bind(policy).bind(transport.as_str()).bind(binding.asset.routing_revision).fetch_one(&mut *tx).await.map_err(db)?;
            sqlx::query("INSERT INTO connections(id,ticket_id,user_id,login_session_id,asset_id,account_id,capabilities,purpose,state,gateway_id,auth_revision,asset_revision,target_host,target_port,target_username,user_snapshot,asset_snapshot,transport,protocol_version,account_revision,policy_revision,routing_revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11,$12,$13,$14,$15,$16,$17,1,$18,$19,$20)")
                .bind(connection).bind(ticket).bind(identity.user.id).bind(identity.login_session_id).bind(request.asset_id).bind(request.account_id).bind(cap_strings(&request.capabilities)).bind(request.purpose.as_str()).bind(self.gateway_id.as_ref()).bind(binding.user.revision).bind(binding.asset.revision).bind(&binding.asset.host).bind(binding.asset.port).bind(&binding.username).bind(&binding.user.username).bind(&binding.asset.name).bind(transport.as_str()).bind(binding.account_revision).bind(policy).bind(binding.asset.routing_revision).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"ticket.issued","connection",Some(connection),request_id,json!({"asset_id":request.asset_id,"account_id":request.account_id,"capabilities":request.capabilities,"transport":transport,"protocol_version":1})).await?;
            tx.commit().await.map_err(db)?;
            Ok(WebSessionResponse {protocol_version:1,session_id:ticket,ws_token:secret.expose().into(),connection_id:connection,expires_at:expiry,capabilities:request.capabilities})
        }).await
    }
    pub async fn consume_ticket(&self, id: Uuid, secret: &str) -> StoreResult<Connection> {
        self.consume_session(id, secret, TicketTransport::Ssh, None)
            .await
    }
    pub async fn consume_web_session(
        &self,
        session_id: Uuid,
        secret: &str,
        identity: &Identity,
    ) -> StoreResult<Connection> {
        self.consume_session(
            session_id,
            secret,
            TicketTransport::Websocket,
            Some(identity),
        )
        .await
    }
    async fn consume_session(
        &self,
        id: Uuid,
        secret: &str,
        transport: TicketTransport,
        identity: Option<&Identity>,
    ) -> StoreResult<Connection> {
        bounded(async {
            let mut tx=self.begin().await?;
            // Non-locking routing lookup is followed by locked identity and target,
            // then the ticket lock. Every revocation holds the same policy lock.
            let route=sqlx::query("SELECT user_id,login_session_id,asset_id,account_id FROM connection_tickets WHERE id=$1 AND transport=$2 AND protocol_version=1").bind(id).bind(transport.as_str()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::TicketInvalid)?;
            if let Some(identity) = identity {
                if identity.user.id != route.get::<Uuid,_>("user_id") || identity.login_session_id != route.get::<Uuid,_>("login_session_id") {
                    return Err(ErrorCode::TicketInvalid);
                }
            }
            // Acquire identity and target locks in order before the ticket lock.
            let _binding=self.binding(&mut tx,route.get("user_id"),route.get("login_session_id"),route.get("asset_id"),route.get("account_id")).await;
            let ticket=sqlx::query("SELECT * FROM connection_tickets WHERE id=$1 AND transport=$2 AND protocol_version=1 FOR UPDATE").bind(id).bind(transport.as_str()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::TicketInvalid)?;
            if ticket.get::<Uuid,_>("user_id") != route.get::<Uuid,_>("user_id")
                || ticket.get::<Uuid,_>("login_session_id") != route.get::<Uuid,_>("login_session_id")
                || ticket.get::<Uuid,_>("asset_id") != route.get::<Uuid,_>("asset_id")
                || ticket.get::<Uuid,_>("account_id") != route.get::<Uuid,_>("account_id") {
                return Err(ErrorCode::TicketInvalid);
            }
            let stored:Vec<u8>=ticket.get("secret_hash");let expected:[u8;32]=stored.try_into().map_err(|_|ErrorCode::InternalError)?;
            if !matches_hash(&expected,secret) {return Err(ErrorCode::TicketInvalid); }
            match ticket.get::<String,_>("state").as_str() {"issued"=>{},"expired"=>return Err(ErrorCode::TicketExpired),"revoked"=>return Err(ErrorCode::TicketStale),_=>return Err(ErrorCode::TicketUsed)}
            // The final connection UPDATE must not introduce another lock wait after
            // checking login, grants and ticket expiry at the actual current time.
            let connection:Uuid=ticket.get("connection_id");
            let pending=sqlx::query("SELECT user_id,login_session_id,asset_id,account_id FROM connections WHERE id=$1 AND ticket_id=$2 AND state='pending' AND transport=$3 AND protocol_version=1 FOR UPDATE")
                .bind(connection).bind(id).bind(transport.as_str()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::TicketInvalid)?;
            for field in ["user_id", "login_session_id", "asset_id", "account_id"] {
                if pending.get::<Uuid,_>(field) != route.get::<Uuid,_>(field) { return Err(ErrorCode::TicketInvalid); }
            }
            // Re-read actual login/grant expiration after any ticket/connection-lock wait.
            // These identity/target locks are already owned by this transaction.
            let binding=self.binding(&mut tx,route.get("user_id"),route.get("login_session_id"),route.get("asset_id"),route.get("account_id")).await;
            let time_valid:bool=sqlx::query_scalar("SELECT expires_at>clock_timestamp() FROM connection_tickets WHERE id=$1").bind(id).fetch_one(&mut *tx).await.map_err(db)?;
            let reason=if !time_valid {Some(ErrorCode::TicketExpired)} else {
                match &binding {
                    Err(code)=>Some(*code),
                    Ok(binding)=>{
                        let policy:i64=sqlx::query_scalar("SELECT policy_revision FROM server_settings WHERE singleton").fetch_one(&mut *tx).await.map_err(db)?;
                        let caps=parse_caps(ticket.get("capabilities"))?;
                        if identity.is_some_and(|identity| identity.user.revision != binding.user.revision) {Some(ErrorCode::LoginSessionRevoked)}
                        else if ticket.get::<String,_>("gateway_id")!=self.gateway_id.as_ref() || ticket.get::<i64,_>("auth_revision")!=binding.user.revision || ticket.get::<i64,_>("routing_revision")!=binding.asset.routing_revision || ticket.get::<i64,_>("account_revision")!=binding.account_revision || ticket.get::<i64,_>("policy_revision")!=policy {Some(ErrorCode::TicketStale)}
                        else if caps.iter().any(|c|!binding.capabilities.contains(c)) {Some(ErrorCode::PermissionDenied)} else {None}
                    }
                }
            };
            if let Some(reason)=reason {
                let state=if reason==ErrorCode::TicketExpired {"expired"}else{"revoked"};
                sqlx::query("UPDATE connection_tickets SET state=$2 WHERE id=$1").bind(id).bind(state).execute(&mut *tx).await.map_err(db)?;
                sqlx::query("UPDATE connections SET state=$2,ended_at=clock_timestamp(),failure_code=$3 WHERE id=$1").bind(connection).bind(state).bind(code_string(reason)).execute(&mut *tx).await.map_err(db)?;
                audit(&mut tx,Some(route.get("user_id")),Some(route.get("login_session_id")),"ticket.rejected","connection",Some(connection),Uuid::new_v4(),json!({"reason_code":reason})).await?;
                tx.commit().await.map_err(db)?;return Err(reason);
            }
            connection_limits(&mut tx,route.get("user_id")).await?;
            let changed=sqlx::query("UPDATE connection_tickets SET state='consumed',consumed_at=clock_timestamp() WHERE id=$1 AND secret_hash=$2 AND state='issued' AND expires_at>clock_timestamp() AND transport=$3 AND protocol_version=1")
                .bind(id).bind(hash(secret).as_slice()).bind(transport.as_str()).execute(&mut *tx).await.map_err(db)?;
            if changed.rows_affected()!=1 {return Err(ErrorCode::TicketExpired); }
            let row=sqlx::query("UPDATE connections SET state='connecting',started_at=clock_timestamp() WHERE id=$1 AND ticket_id=$2 AND state='pending' AND transport=$3 AND protocol_version=1 RETURNING *").bind(connection).bind(id).bind(transport.as_str()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::TicketInvalid)?;
            audit(&mut tx,Some(route.get("user_id")),Some(route.get("login_session_id")),"ticket.consumed","connection",Some(connection),Uuid::new_v4(),json!({})).await?;
            audit(&mut tx,Some(route.get("user_id")),Some(route.get("login_session_id")),"connection.connecting","connection",Some(connection),Uuid::new_v4(),json!({})).await?;
            tx.commit().await.map_err(db)?;connection_view(&row)
        }).await
    }
    pub async fn target_snapshot(&self, connection: &Connection) -> StoreResult<TargetSnapshot> {
        self.account_snapshot(connection.asset_id, connection.account_id)
            .await
    }
    pub async fn account_snapshot(
        &self,
        asset_id: Uuid,
        account_id: Uuid,
    ) -> StoreResult<TargetSnapshot> {
        let row=sqlx::query("SELECT a.host,a.port,t.username,c.* FROM assets a JOIN target_accounts t ON t.asset_id=a.id JOIN credentials c ON c.id=t.credential_id WHERE a.id=$1 AND t.id=$2")
            .bind(asset_id).bind(account_id).fetch_optional(&self.pool).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
        let keys: Vec<String> = sqlx::query_scalar(
            "SELECT public_key FROM asset_host_keys WHERE asset_id=$1 AND state='approved'",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        Ok(TargetSnapshot {
            host: row.get("host"),
            port: u16::try_from(row.get::<i32, _>("port")).map_err(|_| ErrorCode::InternalError)?,
            username: row.get("username"),
            keys,
            context: CipherContext {
                server_id: self.server_id.to_string(),
                credential_id: row.get("id"),
                kind: row.get("kind"),
                revision: row.get("revision"),
            },
            credential: Envelope {
                ciphertext: row.get("ciphertext"),
                nonce: row.get("nonce"),
                wrapped_dek: row.get("wrapped_dek"),
                wrap_nonce: row.get("wrap_nonce"),
                key_version: row.get("key_version"),
            },
        })
    }
    pub async fn authorize_connection(&self, connection: &Connection) -> StoreResult<()> {
        bounded(async {
            let mut tx = self.begin().await?;
            let user_id = connection.user_id.ok_or(ErrorCode::Unauthenticated)?;
            let login_session_id = connection
                .login_session_id
                .ok_or(ErrorCode::Unauthenticated)?;
            // Acquire policy -> identity -> target locks before the connection row.
            self.binding(
                &mut tx,
                user_id,
                login_session_id,
                connection.asset_id,
                connection.account_id,
            )
            .await?;
            let row = sqlx::query("SELECT * FROM connections WHERE id=$1 FOR UPDATE")
                .bind(connection.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
            // The row lock may have waited across a login or grant deadline.
            // Re-read with clock_timestamp(); identity/target locks are already held,
            // so this does not acquire them in reverse order.
            let binding = self
                .binding(
                    &mut tx,
                    user_id,
                    login_session_id,
                    connection.asset_id,
                    connection.account_id,
                )
                .await?;
            if !matches!(
                row.get::<String, _>("state").as_str(),
                "connecting" | "active"
            ) || row.get::<i64, _>("auth_revision") != binding.user.revision
                || row.get::<i64, _>("routing_revision") != binding.asset.routing_revision
                || row.get::<String, _>("target_username") != binding.username
                || connection
                    .capabilities
                    .iter()
                    .any(|c| !binding.capabilities.contains(c))
            {
                return Err(ErrorCode::PermissionDenied);
            }
            tx.commit().await.map_err(db)
        })
        .await
    }
    pub async fn transition(
        &self,
        id: Uuid,
        state: ConnectionState,
        failure: Option<ErrorCode>,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;
            let row=sqlx::query("SELECT * FROM connections WHERE id=$1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            let current=connection_view(&row)?;
            if !current.state.permits(state) {return Ok(()); }
            let terminal=state.is_terminal();
            sqlx::query("UPDATE connections SET state=$2,failure_code=COALESCE($3,failure_code),ended_at=CASE WHEN $4 THEN clock_timestamp() ELSE ended_at END WHERE id=$1")
                .bind(id).bind(state_string(state)).bind(failure.map(code_string)).bind(terminal).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx,current.user_id,current.login_session_id,&format!("connection.{}",state_string(state)),"connection",Some(id),Uuid::new_v4(),json!({"reason_code":failure})).await?;
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn connection(&self, identity: &Identity, id: Uuid) -> StoreResult<Connection> {
        bounded(async {
            let mut tx = self.begin().await?;
            expire_tickets(&mut tx).await?;
            let row = sqlx::query("SELECT * FROM connections WHERE id=$1 AND (user_id=$2 OR $3)")
                .bind(id)
                .bind(identity.user.id)
                .bind(matches!(identity.user.role, Role::Admin | Role::Auditor))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
            tx.commit().await.map_err(db)?;
            connection_view(&row)
        })
        .await
    }
    pub async fn recover_gateway(&self) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;
            let rows=sqlx::query("UPDATE connections SET state='interrupted',ended_at=clock_timestamp() WHERE gateway_id=$1 AND state IN ('connecting','active','closing') RETURNING *").bind(self.gateway_id.as_ref()).fetch_all(&mut *tx).await.map_err(db)?;
            for row in rows {let connection=connection_view(&row)?;audit(&mut tx,connection.user_id,connection.login_session_id,"connection.interrupted","connection",Some(connection.id),Uuid::new_v4(),json!({"reason":"gateway_restart"})).await?;}
            super::maintenance::recover_dependents(&mut tx,self.gateway_id.as_ref()).await?;
            sqlx::query("UPDATE copy_jobs SET state='interrupted',ended_at=clock_timestamp() WHERE gateway_id=$1 AND state IN ('queued','running')").bind(self.gateway_id.as_ref()).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("UPDATE connection_tickets SET state='revoked' WHERE gateway_id=$1 AND state='issued'").bind(self.gateway_id.as_ref()).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("UPDATE connections SET state='revoked',ended_at=clock_timestamp() WHERE gateway_id=$1 AND state='pending'").bind(self.gateway_id.as_ref()).execute(&mut *tx).await.map_err(db)?;
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn channel_audit(
        &self,
        connection: &Connection,
        kind: &str,
        command_hash: Option<String>,
        command_len: Option<usize>,
    ) -> StoreResult<()> {
        let mut tx = self.begin().await?;
        audit(
            &mut tx,
            connection.user_id,
            connection.login_session_id,
            if kind == "exec" {
                "exec.requested"
            } else {
                "channel.started"
            },
            "connection",
            Some(connection.id),
            Uuid::new_v4(),
            json!({"kind":kind,"command_sha256":command_hash,"command_bytes":command_len}),
        )
        .await?;
        tx.commit().await.map_err(db)
    }
    pub async fn request_disconnect(
        &self,
        identity: &Identity,
        id: Uuid,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,identity,false).await?;
            let row=sqlx::query("SELECT * FROM connections WHERE id=$1 AND (user_id=$2 OR $3) FOR UPDATE").bind(id).bind(identity.user.id).bind(identity.user.role==Role::Admin).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            let connection=connection_view(&row)?;
            if matches!(connection.state,ConnectionState::Connecting|ConnectionState::Active) {
                sqlx::query("UPDATE connections SET state='closing' WHERE id=$1").bind(id).execute(&mut *tx).await.map_err(db)?;
            } else if connection.state==ConnectionState::Pending {
                sqlx::query("UPDATE connections SET state='revoked',ended_at=clock_timestamp() WHERE id=$1").bind(id).execute(&mut *tx).await.map_err(db)?;
                sqlx::query("UPDATE connection_tickets SET state='revoked' WHERE connection_id=$1 AND state='issued'").bind(id).execute(&mut *tx).await.map_err(db)?;
            }
            audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"connection.disconnect_requested","connection",Some(id),request_id,json!({})).await?;
            tx.commit().await.map_err(db)
        }).await
    }
}
pub(super) async fn expire_tickets(tx: &mut Transaction<'_, Postgres>) -> StoreResult<()> {
    sqlx::query("UPDATE connection_tickets SET state='expired' WHERE state='issued' AND expires_at<=clock_timestamp()").execute(&mut **tx).await.map_err(db)?;
    sqlx::query("UPDATE connections c SET state='expired',ended_at=clock_timestamp() FROM connection_tickets t WHERE c.ticket_id=t.id AND c.state='pending' AND t.state='expired'").execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
async fn connection_limits(tx: &mut Transaction<'_, Postgres>, user: Uuid) -> StoreResult<()> {
    let row=sqlx::query("SELECT count(*) AS total,count(*) FILTER(WHERE user_id=$1) AS per_user FROM connections WHERE state IN ('connecting','active','closing')").bind(user).fetch_one(&mut **tx).await.map_err(db)?;
    if row.get::<i64, _>("total") >= 100 || row.get::<i64, _>("per_user") >= 10 {
        return Err(ErrorCode::ConnectionLimit);
    }
    Ok(())
}
fn state_string(state: ConnectionState) -> String {
    serde_json::to_value(state)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}
fn code_string(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}
pub(super) fn connection_view(row: &PgRow) -> StoreResult<Connection> {
    let state = match row.get::<String, _>("state").as_str() {
        "pending" => ConnectionState::Pending,
        "connecting" => ConnectionState::Connecting,
        "active" => ConnectionState::Active,
        "closing" => ConnectionState::Closing,
        "closed" => ConnectionState::Closed,
        "failed" => ConnectionState::Failed,
        "expired" => ConnectionState::Expired,
        "revoked" => ConnectionState::Revoked,
        "interrupted" => ConnectionState::Interrupted,
        _ => return Err(ErrorCode::InternalError),
    };
    let purpose = match row.get::<String, _>("purpose").as_str() {
        "terminal" => Purpose::Terminal,
        "sftp" => Purpose::Sftp,
        "metrics" => Purpose::Metrics,
        "server_tool" => Purpose::ServerTool,
        _ => return Err(ErrorCode::InternalError),
    };
    let failure = row
        .get::<Option<String>, _>("failure_code")
        .map(|s| serde_json::from_value::<ErrorCode>(json!(s)).map(|code| Failure { code }))
        .transpose()
        .map_err(|_| ErrorCode::InternalError)?;
    Ok(Connection {
        id: row.get("id"),
        ticket_id: row.get("ticket_id"),
        asset_id: row.get("asset_id"),
        account_id: row.get("account_id"),
        capabilities: parse_caps(row.get("capabilities"))?,
        purpose,
        transport: match row.get::<String, _>("transport").as_str() {
            "ssh" => TicketTransport::Ssh,
            "websocket" => TicketTransport::Websocket,
            _ => return Err(ErrorCode::InternalError),
        },
        protocol_version: u32::try_from(row.get::<i32, _>("protocol_version"))
            .map_err(|_| ErrorCode::InternalError)?,
        state,
        created_at: row.get("created_at"),
        failure,
        user_id: Some(row.get("user_id")),
        login_session_id: Some(row.get("login_session_id")),
    })
}

fn user_view(row: &PgRow) -> StoreResult<UserView> {
    let role = match row.get::<String, _>("role").as_str() {
        "admin" => Role::Admin,
        "operator" => Role::Operator,
        "auditor" => Role::Auditor,
        _ => return Err(ErrorCode::InternalError),
    };
    Ok(UserView {
        id: row.get("id"),
        username: row.get("username"),
        role,
        enabled: row.get("enabled"),
        revision: row.get("auth_revision"),
    })
}
fn identity_from_row(row: &PgRow) -> StoreResult<Identity> {
    let user = user_view(row)?;
    if !user.enabled {
        return Err(ErrorCode::UserDisabled);
    }
    if row.get::<Option<DateTime<Utc>>, _>("revoked_at").is_some()
        || !row.get::<bool, _>("session_valid")
    {
        return Err(ErrorCode::LoginSessionRevoked);
    }
    if !row.get::<bool, _>("token_valid") {
        return Err(ErrorCode::AccessTokenExpired);
    }
    Ok(Identity {
        user,
        login_session_id: row.get("session_id"),
    })
}
async fn insert_user(
    tx: &mut Transaction<'_, Postgres>,
    username: &str,
    password_hash: &str,
    role: Role,
) -> StoreResult<UserView> {
    let row = sqlx::query(
        "INSERT INTO users(id,username,password_hash,role) VALUES($1,$2,$3,$4) RETURNING *",
    )
    .bind(Uuid::new_v4())
    .bind(username)
    .bind(password_hash)
    .bind(role.as_str())
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    user_view(&row)
}
async fn insert_tokens(
    tx: &mut Transaction<'_, Postgres>,
    session: Uuid,
    access: &Secret,
    refresh: &Secret,
    expiry: DateTime<Utc>,
) -> StoreResult<DateTime<Utc>> {
    insert_tokens_with_id(tx, session, Uuid::new_v4(), access, refresh, expiry).await
}
async fn insert_tokens_with_id(
    tx: &mut Transaction<'_, Postgres>,
    session: Uuid,
    id: Uuid,
    access: &Secret,
    refresh: &Secret,
    expiry: DateTime<Utc>,
) -> StoreResult<DateTime<Utc>> {
    sqlx::query("INSERT INTO refresh_tokens(id,login_session_id,token_hash,state,expires_at) VALUES($1,$2,$3,'active',$4)").bind(id).bind(session).bind(refresh.hash().as_slice()).bind(expiry).execute(&mut **tx).await.map_err(db)?;
    sqlx::query_scalar("INSERT INTO access_tokens(token_hash,login_session_id,expires_at) VALUES($1,$2,LEAST(clock_timestamp()+interval '10 minutes',$3)) RETURNING expires_at").bind(access.hash().as_slice()).bind(session).bind(expiry).fetch_one(&mut **tx).await.map_err(db)
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    actor: Option<Uuid>,
    session: Option<Uuid>,
    action: &str,
    kind: &str,
    resource: Option<Uuid>,
    request_id: Uuid,
    payload: Value,
) -> StoreResult<()> {
    sqlx::query("INSERT INTO audit_events(id,actor_id,login_session_id,action,resource_type,resource_id,request_id,sanitized_payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(Uuid::new_v4()).bind(actor).bind(session).bind(action).bind(kind).bind(resource).bind(request_id).bind(payload).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
pub(super) async fn revoke_session(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> StoreResult<()> {
    sqlx::query(
        "UPDATE login_sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    // Retain only token hashes for idempotent logout; revoked sessions never authenticate.
    sqlx::query(
        "UPDATE refresh_tokens SET state='revoked' WHERE login_session_id=$1 AND state='active'",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    sqlx::query("UPDATE connection_tickets SET state='revoked' WHERE login_session_id=$1 AND state='issued'").bind(id).execute(&mut **tx).await.map_err(db)?;
    sqlx::query("UPDATE connections SET state='revoked',ended_at=clock_timestamp() WHERE login_session_id=$1 AND state='pending'").bind(id).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
async fn revoke_user(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> StoreResult<()> {
    let sessions: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM login_sessions WHERE user_id=$1 AND revoked_at IS NULL")
            .bind(id)
            .fetch_all(&mut **tx)
            .await
            .map_err(db)?;
    for session in sessions {
        revoke_session(tx, session).await?;
    }
    Ok(())
}

impl PgStore {
    pub async fn account_test_audit(
        &self,
        actor: &Identity,
        account: Uuid,
        request_id: Uuid,
        result: Option<ErrorCode>,
        completed: bool,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;
            self.actor(&mut tx,actor,true).await?;
            let row=sqlx::query("SELECT t.id,t.enabled AS account_enabled,a.enabled AS asset_enabled FROM target_accounts t JOIN assets a ON a.id=t.asset_id WHERE t.id=$1 FOR UPDATE OF a,t").bind(account).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            if !row.get::<bool,_>("account_enabled") || !row.get::<bool,_>("asset_enabled") {return Err(ErrorCode::PermissionDenied);}
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),if completed{"account.test_completed"}else{"account.test_requested"},"account",Some(account),request_id,json!({"reason_code":result,"authenticated":completed&&result.is_none()})).await?;
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn user(&self, id: Uuid) -> StoreResult<UserView> {
        let row =
            sqlx::query("SELECT id,username,role,enabled,auth_revision FROM users WHERE id=$1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
        user_view(&row)
    }
    pub async fn grant(&self, id: Uuid) -> StoreResult<GrantView> {
        let row = sqlx::query("SELECT * FROM grants WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or(ErrorCode::ResourceNotFound)?;
        grant_view(&row)
    }
}

async fn invalidate_grant(tx: &mut Transaction<'_, Postgres>, row: &PgRow) -> StoreResult<()> {
    sqlx::query("UPDATE connection_tickets SET state='revoked' WHERE user_id=$1 AND asset_id=$2 AND account_id=$3 AND state='issued'").bind(row.get::<Uuid,_>("user_id")).bind(row.get::<Uuid,_>("asset_id")).bind(row.get::<Uuid,_>("account_id")).execute(&mut **tx).await.map_err(db)?;
    sqlx::query("UPDATE connections c SET state='revoked',ended_at=clock_timestamp() FROM connection_tickets t WHERE c.ticket_id=t.id AND c.state='pending' AND t.state='revoked'").execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
impl PgStore {
    #[allow(clippy::too_many_arguments)]
    pub async fn update_grant(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        caps: Option<&[Capability]>,
        enabled: Option<bool>,
        expires: Option<Option<DateTime<Utc>>>,
        request_id: Uuid,
    ) -> StoreResult<GrantView> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
            let row=sqlx::query("UPDATE grants SET capabilities=COALESCE($3,capabilities),enabled=COALESCE($4,enabled),expires_at=CASE WHEN $5 THEN $6 ELSE expires_at END,revision=revision+1 WHERE id=$1 AND revision=$2 RETURNING *").bind(id).bind(revision).bind(caps.map(cap_strings)).bind(enabled).bind(expires.is_some()).bind(expires.flatten()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::RevisionConflict)?;
            bump_policy(&mut tx).await?;invalidate_grant(&mut tx,&row).await?;
            audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"grant.updated","grant",Some(id),request_id,json!({"capabilities":caps,"enabled":enabled,"expires_at":expires})).await?;
            tx.commit().await.map_err(db)?;grant_view(&row)
        }).await
    }
}

impl PgStore {
    pub async fn logout_completed(&self, token: &str) -> StoreResult<bool> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM access_tokens t JOIN login_sessions s ON s.id=t.login_session_id WHERE t.token_hash=$1 AND s.client_type='zeroterm' AND s.revoked_at IS NOT NULL)").bind(hash(token).as_slice()).fetch_one(&self.pool).await.map_err(db)
    }
}

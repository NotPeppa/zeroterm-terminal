use bastion_domain::*;
use bastion_secrets::{hash, Secret};
use chrono::{DateTime, Utc};
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
    session_limits: Arc<std::sync::RwLock<[i64; 3]>>,
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
            session_limits: Arc::new(std::sync::RwLock::new([10, 3, 20])),
        })
    }
    /// Configure frozen launch-time ceilings once before serving; clones share the counts.
    pub fn configure_session_limits(
        &self,
        global: usize,
        user: usize,
        pending: usize,
    ) -> StoreResult<()> {
        if !(1..=10).contains(&global)
            || !(1..=3).contains(&user)
            || user > global
            || !(1..=20).contains(&pending)
        {
            return Err(ErrorCode::InvalidArgument);
        }
        *self
            .session_limits
            .write()
            .map_err(|_| ErrorCode::InternalError)? = [global as i64, user as i64, pending as i64];
        Ok(())
    }
    pub(super) fn session_limits(&self) -> StoreResult<[i64; 3]> {
        self.session_limits
            .read()
            .map(|limits| *limits)
            .map_err(|_| ErrorCode::InternalError)
    }
    pub async fn migrate(&self) -> StoreResult<()> {
        // Absolutely no migrator call, checksum rewrite or DROP against schema family 1.
        let settings: bool =
            sqlx::query_scalar("SELECT to_regclass('server_settings') IS NOT NULL")
                .fetch_one(&self.pool)
                .await
                .map_err(db)?;
        if settings {
            let version: Option<i32> =
                sqlx::query_scalar("SELECT schema_version FROM server_settings WHERE singleton")
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db)?;
            if version != Some(2) {
                return Err(ErrorCode::ResourceConflict);
            }
        } else {
            let populated:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND (c.relname<>'_sqlx_migrations' OR n.nspname<>current_schema()))").fetch_one(&self.pool).await.map_err(db)?;
            let ledger: bool =
                sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
                    .fetch_one(&self.pool)
                    .await
                    .map_err(db)?;
            let ledger_populated = if ledger {
                sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations)")
                    .fetch_one(&self.pool)
                    .await
                    .map_err(db)?
            } else {
                false
            };
            if populated || ledger_populated {
                return Err(ErrorCode::ResourceConflict);
            }
        }
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|_| ErrorCode::PolicyStoreUnavailable)?;
        sqlx::query("INSERT INTO server_settings(singleton,server_id) VALUES(true,$1) ON CONFLICT DO NOTHING").bind(self.server_id.as_ref()).execute(&self.pool).await.map_err(db)?;
        self.check_identity().await
    }
    pub async fn check_identity(&self) -> StoreResult<()> {
        let id: String = sqlx::query_scalar(
            "SELECT server_id FROM server_settings WHERE singleton AND schema_version=2",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        if id != self.server_id.as_ref() {
            return Err(ErrorCode::ResourceConflict);
        }
        let schema_ready: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=6 AND success)",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        if !schema_ready {
            return Err(ErrorCode::PolicyStoreUnavailable);
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
    /// Whether any administrator exists, deleted ones included: bootstrap must never run twice.
    pub async fn admin_exists(&self) -> StoreResult<bool> {
        bounded(async {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE role='admin')")
                .fetch_one(&self.pool)
                .await
                .map_err(db)
        })
        .await
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
        let row = sqlx::query("SELECT * FROM users WHERE username=$1 AND deleted_at IS NULL")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| Ok((user_view(&r)?, r.get("password_hash"))))
            .transpose()
    }
    pub async fn login_web(
        &self,
        verified: &UserView,
        verified_hash: &str,
        label: &str,
        request_id: Uuid,
    ) -> StoreResult<LoginResponse> {
        self.login_inner(verified, verified_hash, label, request_id)
            .await
    }
    async fn login_inner(
        &self,
        verified: &UserView,
        verified_hash: &str,
        label: &str,
        request_id: Uuid,
    ) -> StoreResult<LoginResponse> {
        bounded(async {
            let mut tx=self.begin().await?;
            let row=sqlx::query("SELECT * FROM users WHERE id=$1 FOR UPDATE").bind(verified.id).fetch_one(&mut *tx).await.map_err(db)?;
            let user=user_view(&row)?;
            if !user.enabled || user.revision!=verified.revision || row.get::<String,_>("password_hash")!=verified_hash {return Err(ErrorCode::Unauthenticated); }
            let access=Secret::random();let refresh=Secret::random();let session=Uuid::new_v4();
            let expiry:DateTime<Utc>=sqlx::query_scalar("INSERT INTO login_sessions(id,user_id,device_label,family_id,refresh_hash,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '7 days') RETURNING expires_at")
                .bind(session).bind(user.id).bind(label).bind(Uuid::new_v4()).bind(refresh.hash().as_slice()).fetch_one(&mut *tx).await.map_err(db)?;
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
    pub async fn authenticate_web(&self, secret: &str) -> StoreResult<Identity> {
        let row=sqlx::query("SELECT u.*,s.id AS session_id,s.revoked_at,s.expires_at>clock_timestamp() AS session_valid,t.expires_at>clock_timestamp() AS token_valid,t.expires_at AS token_expires_at FROM access_tokens t JOIN login_sessions s ON s.id=t.login_session_id JOIN users u ON u.id=s.user_id WHERE t.token_hash=$1").bind(hash(secret).as_slice()).fetch_optional(&self.pool).await.map_err(db)?.ok_or(ErrorCode::Unauthenticated)?;
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
        if current.user.revision != identity.user.revision
            || current.user.role != identity.user.role
        {
            return Err(ErrorCode::LoginSessionRevoked);
        }
        if admin && current.user.role != Role::Admin {
            return Err(ErrorCode::PermissionDenied);
        }
        Ok(())
    }
    pub async fn refresh_web(&self, secret: &str, request_id: Uuid) -> StoreResult<LoginResponse> {
        self.refresh_inner(secret, request_id).await
    }
    async fn refresh_inner(&self, secret: &str, request_id: Uuid) -> StoreResult<LoginResponse> {
        bounded(async {
            // Policy lock precedes identity/token locks, including replay revocation.
            let mut tx=self.begin().await?;
            let row=sqlx::query("SELECT r.id AS refresh_id,r.state,r.expires_at>clock_timestamp() AS refresh_valid,u.*,s.id AS session_id,s.revoked_at,s.expires_at AS family_expiry,s.expires_at>clock_timestamp() AS session_valid,true AS token_valid FROM refresh_tokens r JOIN login_sessions s ON s.id=r.login_session_id JOIN users u ON u.id=s.user_id WHERE r.token_hash=$1 FOR UPDATE OF u,s,r")
                .bind(hash(secret).as_slice()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::Unauthenticated)?;
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
        sqlx::query("SELECT id,username,role,enabled,auth_revision FROM users WHERE deleted_at IS NULL ORDER BY created_at,id LIMIT 200").fetch_all(&self.pool).await.map_err(db)?.iter().map(user_view).collect()
    }
    pub async fn delete_user(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, actor, true).await?;
            if id == actor.user.id {
                return Err(ErrorCode::PermissionDenied);
            }
            lock_user_revision(&mut tx, id, revision).await?;
            sqlx::query("UPDATE users SET deleted_at=clock_timestamp(),enabled=false,auth_revision=auth_revision+1 WHERE id=$1")
                .bind(id).execute(&mut *tx).await.map_err(db)?;
            revoke_user(&mut tx, id).await?;
            sqlx::query("UPDATE connections SET state='closing' WHERE user_id=$1 AND state IN ('active','connecting')")
                .bind(id).execute(&mut *tx).await.map_err(db)?;
            audit(
                &mut tx,
                Some(actor.user.id),
                Some(actor.login_session_id),
                "user.deleted",
                "user",
                Some(id),
                request_id,
                json!({}),
            )
            .await?;
            tx.commit().await.map_err(db)
        })
        .await
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
            lock_user_revision(&mut tx,id,revision).await?;
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
            lock_user_revision(&mut tx,id,revision).await?;
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
}
impl PgStore {
    pub async fn transition(
        &self,
        id: Uuid,
        state: ConnectionState,
        failure: Option<ErrorCode>,
    ) -> StoreResult<()> {
        // Consumption and recording activation own these atomic transitions.
        if matches!(state, ConnectionState::Connecting | ConnectionState::Active) {
            return Err(ErrorCode::InvalidArgument);
        }
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
            self.actor(&mut tx, identity, false).await?;
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
            sqlx::query("UPDATE connection_tickets SET state='revoked' WHERE gateway_id=$1 AND state='issued'").bind(self.gateway_id.as_ref()).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("UPDATE connections SET state='revoked',ended_at=clock_timestamp() WHERE gateway_id=$1 AND state='pending'").bind(self.gateway_id.as_ref()).execute(&mut *tx).await.map_err(db)?;
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn request_disconnect(
        &self,
        identity: &Identity,
        id: Uuid,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,identity,false).await?;
            if identity.user.role==Role::Auditor {return Err(ErrorCode::PermissionDenied);}
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
pub(super) fn state_string(state: ConnectionState) -> String {
    serde_json::to_value(state)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}
pub(super) fn code_string(code: ErrorCode) -> String {
    serde_json::to_value(code)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}
async fn lock_user_revision(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    revision: i64,
) -> StoreResult<()> {
    let current: i64 = sqlx::query_scalar(
        "SELECT auth_revision FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?
    .ok_or(ErrorCode::ResourceNotFound)?;
    if current != revision {
        return Err(ErrorCode::RevisionConflict);
    }
    Ok(())
}
pub(super) fn user_view(row: &PgRow) -> StoreResult<UserView> {
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
pub(super) fn identity_from_row(row: &PgRow) -> StoreResult<Identity> {
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
        access_expires_at: row.try_get("token_expires_at").ok().flatten(),
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
    pub async fn user(&self, id: Uuid) -> StoreResult<UserView> {
        let row =
            sqlx::query("SELECT id,username,role,enabled,auth_revision FROM users WHERE id=$1 AND deleted_at IS NULL")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
        user_view(&row)
    }
    pub async fn logout_completed(&self, token: &str) -> StoreResult<bool> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM access_tokens t JOIN login_sessions s ON s.id=t.login_session_id WHERE t.token_hash=$1 AND s.revoked_at IS NOT NULL)").bind(hash(token).as_slice()).fetch_one(&self.pool).await.map_err(db)
    }
}

pub(super) fn connection_view(r: &PgRow) -> StoreResult<Connection> {
    let parse =
        |field: &str| -> StoreResult<serde_json::Value> { Ok(json!(r.get::<String, _>(field))) };
    Ok(Connection {
        id: r.get("id"),
        ticket_id: r.get("ticket_id"),
        asset_id: r.get("asset_id"),
        account_id: r.get("account_id"),
        target_protocol: serde_json::from_value(parse("target_protocol")?)
            .map_err(|_| ErrorCode::InternalError)?,
        display: Display {
            width: r.get::<i32, _>("width") as u32,
            height: r.get::<i32, _>("height") as u32,
            dpi: r.get::<i32, _>("dpi") as u32,
        },
        protocol_version: r.get::<i32, _>("protocol_version") as u32,
        state: serde_json::from_value(parse("state")?).map_err(|_| ErrorCode::InternalError)?,
        created_at: r.get("created_at"),
        failure: r
            .get::<Option<String>, _>("failure_code")
            .map(|s| serde_json::from_value::<ErrorCode>(json!(s)).map(|code| Failure { code }))
            .transpose()
            .map_err(|_| ErrorCode::InternalError)?,
        user_id: Some(r.get("user_id")),
        login_session_id: Some(r.get("login_session_id")),
        auth_revision: r.get("auth_revision"),
        routing_revision: r.get("routing_revision"),
        account_revision: r.get("account_revision"),
        credential_revision: r.get("credential_revision"),
    })
}

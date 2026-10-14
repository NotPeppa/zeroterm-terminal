use crate::{
    inputs::{validate_account, validate_credential_input},
    postgres::*,
    *,
};
use bastion_domain::*;
use bastion_secrets::{CipherContext, Credential, Envelope, KeyRing};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use uuid::Uuid;
#[derive(Clone, Serialize)]
pub struct AssetView {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: i32,
    pub tags: Vec<String>,
    pub group_id: Option<Uuid>,
    pub enabled: bool,
    pub revision: i64,
    pub routing_revision: i64,
    pub protocol: TargetProtocol,
    pub security: Option<RdpSecurity>,
    pub ssh_host_key: Option<String>,
    pub rdp_certificate_sha256: Option<String>,
}
#[derive(Clone, Serialize)]
pub struct AccountView {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub label: String,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub enabled: bool,
    pub revision: i64,
    pub credential_kind: String,
    pub credential_revision: Option<i64>,
}
#[derive(Clone, Serialize)]
pub struct GrantView {
    pub id: Uuid,
    pub user_id: Uuid,
    pub asset_id: Uuid,
    pub account_id: Uuid,
    pub enabled: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub revision: i64,
}
pub struct TargetSnapshot {
    pub host: String,
    pub port: u16,
    pub protocol: TargetProtocol,
    pub security: Option<RdpSecurity>,
    pub ssh_host_key: Option<String>,
    pub rdp_certificate_sha256: Option<String>,
    pub username: Option<String>,
    pub domain: Option<String>,
    pub credential: Option<Envelope>,
    pub context: Option<CipherContext>,
}
pub(super) fn parse<T: serde::de::DeserializeOwned>(s: String) -> StoreResult<T> {
    serde_json::from_value(json!(s)).map_err(|_| ErrorCode::InternalError)
}
pub(super) fn asset_view(r: &PgRow) -> StoreResult<AssetView> {
    Ok(AssetView {
        id: r.get("id"),
        name: r.get("name"),
        host: r.get("host"),
        port: r.get("port"),
        tags: r.get("tags"),
        group_id: r.get("group_id"),
        enabled: r.get("enabled"),
        revision: r.get("config_revision"),
        routing_revision: r.get("routing_revision"),
        protocol: parse(r.get("protocol"))?,
        security: r
            .get::<Option<String>, _>("security")
            .map(parse)
            .transpose()?,
        ssh_host_key: r.get("ssh_host_key"),
        rdp_certificate_sha256: r.get("rdp_certificate_sha256"),
    })
}
fn account_view(r: &PgRow) -> AccountView {
    AccountView {
        id: r.get("id"),
        asset_id: r.get("asset_id"),
        label: r.get("label"),
        username: r.get("username"),
        domain: r.get("domain"),
        enabled: r.get("enabled"),
        revision: r.get("config_revision"),
        credential_kind: r
            .get::<Option<String>, _>("kind")
            .unwrap_or_else(|| "none".into()),
        credential_revision: r.get("credential_revision"),
    }
}
fn grant_view(r: &PgRow) -> GrantView {
    GrantView {
        id: r.get("id"),
        user_id: r.get("user_id"),
        asset_id: r.get("asset_id"),
        account_id: r.get("account_id"),
        enabled: r.get("enabled"),
        expires_at: r.get("expires_at"),
        revision: r.get("revision"),
    }
}
const ACCOUNT_SELECT:&str="SELECT a.*,c.kind,c.revision AS credential_revision FROM target_accounts a LEFT JOIN credentials c ON c.id=a.credential_id";
impl PgStore {
    pub async fn create_asset(
        &self,
        actor: &Identity,
        input: &AssetCreate,
        request_id: Uuid,
    ) -> StoreResult<AssetView> {
        let mut input = input.clone();
        input.validate()?;
        bounded(async {let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
   super::groups::require_group(&mut tx,input.group_id).await?;let row=sqlx::query("INSERT INTO assets(id,name,host,port,tags,protocol,security,ssh_host_key,rdp_certificate_sha256,group_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *").bind(Uuid::new_v4()).bind(&input.name).bind(&input.host).bind(i32::from(input.port)).bind(&input.tags).bind(input.protocol.as_str()).bind(input.security.map(RdpSecurity::as_str)).bind(&input.ssh_host_key).bind(&input.rdp_certificate_sha256).bind(input.group_id).fetch_one(&mut *tx).await.map_err(db)?;let asset=asset_view(&row)?;
   audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"asset.created","asset",Some(asset.id),request_id,json!({"protocol":asset.protocol})).await?;tx.commit().await.map_err(db)?;Ok(asset)
  }).await
    }
    pub async fn asset(&self, id: Uuid) -> StoreResult<AssetView> {
        let row = sqlx::query("SELECT * FROM assets WHERE id=$1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or(ErrorCode::ResourceNotFound)?;
        asset_view(&row)
    }
    pub async fn admin_assets(&self) -> StoreResult<Vec<AssetView>> {
        sqlx::query("SELECT * FROM assets WHERE deleted_at IS NULL ORDER BY created_at,id")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?
            .iter()
            .map(asset_view)
            .collect()
    }
    pub async fn update_asset(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        input: &AssetUpdate,
        request_id: Uuid,
    ) -> StoreResult<AssetView> {
        if input.name.is_none()
            && input.host.is_none()
            && input.port.is_none()
            && input.tags.is_none()
            && input.group_id.is_none()
            && input.enabled.is_none()
            && input.security.is_none()
            && input.ssh_host_key.is_none()
            && input.rdp_certificate_sha256.is_none()
        {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async {let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;let before=sqlx::query("SELECT * FROM assets WHERE id=$1 AND deleted_at IS NULL FOR UPDATE").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;let before=asset_view(&before)?;if revision!=before.revision {return Err(ErrorCode::RevisionConflict);}
   let mut next=AssetCreate{name:input.name.clone().unwrap_or_else(||before.name.clone()),host:input.host.clone().unwrap_or_else(||before.host.clone()),port:input.port.unwrap_or(before.port as u16),tags:input.tags.clone().unwrap_or_else(||before.tags.clone()),group_id:input.group_id.unwrap_or(before.group_id),protocol:before.protocol,security:input.security.unwrap_or(before.security),ssh_host_key:input.ssh_host_key.clone().unwrap_or_else(||before.ssh_host_key.clone()),rdp_certificate_sha256:input.rdp_certificate_sha256.clone().unwrap_or_else(||before.rdp_certificate_sha256.clone())};
   if before.protocol==TargetProtocol::Rdp && input.security==Some(None) {return Err(ErrorCode::InvalidArgument);}next.validate()?;super::groups::require_group(&mut tx,next.group_id).await?;
   let enabled=input.enabled.unwrap_or(before.enabled);let changed=next.host!=before.host || i32::from(next.port)!=before.port || enabled!=before.enabled || next.security!=before.security || next.ssh_host_key!=before.ssh_host_key || next.rdp_certificate_sha256!=before.rdp_certificate_sha256;
   let row=sqlx::query("UPDATE assets SET name=$3,host=$4,port=$5,tags=$6,enabled=$7,security=$8,ssh_host_key=$9,rdp_certificate_sha256=$10,group_id=$12,config_revision=config_revision+1,routing_revision=routing_revision+CASE WHEN $11 THEN 1 ELSE 0 END WHERE id=$1 AND config_revision=$2 RETURNING *").bind(id).bind(revision).bind(next.name).bind(next.host).bind(i32::from(next.port)).bind(next.tags).bind(enabled).bind(next.security.map(RdpSecurity::as_str)).bind(next.ssh_host_key).bind(next.rdp_certificate_sha256).bind(changed).bind(next.group_id).fetch_one(&mut *tx).await.map_err(db)?;
   if changed {invalidate_asset(&mut tx,id).await?;}audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"asset.updated","asset",Some(id),request_id,json!({"security_changed":changed,"group_id":next.group_id})).await?;tx.commit().await.map_err(db)?;asset_view(&row)
  }).await
    }
    pub async fn create_account(
        &self,
        actor: &Identity,
        asset: Uuid,
        input: &AccountCreate,
        keys: &KeyRing,
        request_id: Uuid,
    ) -> StoreResult<AccountView> {
        validate_credential_input(&input.credential).await?;
        bounded(async{let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;let protocol:String=sqlx::query_scalar("SELECT protocol FROM assets WHERE id=$1 AND deleted_at IS NULL FOR UPDATE").bind(asset).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
   validate_account(parse(protocol)?,&input.label,input.username.as_deref(),input.domain.as_deref(),&input.credential)?;
   let credential=write_credential(self,&mut tx,None,&input.credential,keys).await?;let id=Uuid::new_v4();sqlx::query("INSERT INTO target_accounts(id,asset_id,label,username,domain,credential_id) VALUES($1,$2,$3,$4,$5,$6)").bind(id).bind(asset).bind(&input.label).bind(&input.username).bind(&input.domain).bind(credential).execute(&mut *tx).await.map_err(db)?;
   audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"account.created","account",Some(id),request_id,json!({"asset_id":asset,"credential_kind":input.credential.kind()})).await?;tx.commit().await.map_err(db)?;self.account(id).await
  }).await
    }
    pub async fn account(&self, id: Uuid) -> StoreResult<AccountView> {
        let row = sqlx::query(&format!(
            "{ACCOUNT_SELECT} WHERE a.id=$1 AND a.deleted_at IS NULL"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .ok_or(ErrorCode::ResourceNotFound)?;
        Ok(account_view(&row))
    }
    pub async fn accounts(&self, asset: Uuid) -> StoreResult<Vec<AccountView>> {
        Ok(sqlx::query(&format!(
            "{ACCOUNT_SELECT} WHERE a.asset_id=$1 AND a.deleted_at IS NULL ORDER BY a.id LIMIT 200"
        ))
        .bind(asset)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .iter()
        .map(account_view)
        .collect())
    }
    /// Administrator deletion. Like users.deleted_at this is a soft delete: the row survives so that
    /// connection, ticket and audit history keeps its foreign keys, but the asset and every account
    /// under it leave the catalogs at once, outstanding tickets are revoked and live sessions are closed.
    pub async fn delete_asset(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, actor, true).await?;
            let before = sqlx::query("SELECT * FROM assets WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
            if before.get::<i64, _>("config_revision") != revision {
                return Err(ErrorCode::RevisionConflict);
            }
            let accounts = sqlx::query("UPDATE target_accounts SET deleted_at=clock_timestamp(),enabled=false,config_revision=config_revision+1 WHERE asset_id=$1 AND deleted_at IS NULL")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db)?
                .rows_affected();
            let grants = sqlx::query("UPDATE grants SET enabled=false,revision=revision+1 WHERE asset_id=$1 AND enabled")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db)?
                .rows_affected();
            sqlx::query("UPDATE assets SET deleted_at=clock_timestamp(),enabled=false,config_revision=config_revision+1 WHERE id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            let closed = close_connections(&mut tx, "asset_id=$1", id).await?;
            invalidate_asset(&mut tx, id).await?;
            audit(
                &mut tx,
                Some(actor.user.id),
                Some(actor.login_session_id),
                "asset.deleted",
                "asset",
                Some(id),
                request_id,
                json!({"name": before.get::<String, _>("name"), "accounts_deleted": accounts, "grants_revoked": grants, "connections_closed": closed}),
            )
            .await?;
            tx.commit().await.map_err(db)
        })
        .await
    }
    /// Administrator deletion of one target account; sibling accounts and the asset are untouched.
    pub async fn delete_account(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, actor, true).await?;
            let before = sqlx::query("SELECT * FROM target_accounts WHERE id=$1 AND deleted_at IS NULL FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
            if before.get::<i64, _>("config_revision") != revision {
                return Err(ErrorCode::RevisionConflict);
            }
            let grants = sqlx::query("UPDATE grants SET enabled=false,revision=revision+1 WHERE account_id=$1 AND enabled")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db)?
                .rows_affected();
            sqlx::query("UPDATE target_accounts SET deleted_at=clock_timestamp(),enabled=false,config_revision=config_revision+1 WHERE id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            let closed = close_connections(&mut tx, "account_id=$1", id).await?;
            invalidate_account(&mut tx, id).await?;
            audit(
                &mut tx,
                Some(actor.user.id),
                Some(actor.login_session_id),
                "account.deleted",
                "account",
                Some(id),
                request_id,
                json!({"asset_id": before.get::<Uuid, _>("asset_id"), "label": before.get::<String, _>("label"), "grants_revoked": grants, "connections_closed": closed}),
            )
            .await?;
            tx.commit().await.map_err(db)
        })
        .await
    }
    pub async fn update_account(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        input: &AccountUpdate,
        keys: &KeyRing,
        request_id: Uuid,
    ) -> StoreResult<AccountView> {
        if let Some(credential) = &input.credential {
            validate_credential_input(credential).await?;
        }
        if input.label.is_none()
            && input.username.is_none()
            && input.domain.is_none()
            && input.enabled.is_none()
            && input.credential.is_none()
        {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async{let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;
   // Lock only nonnullable parent/account rows. A credential is locked separately if present.
   let before=sqlx::query("SELECT a.*,s.protocol FROM assets s JOIN target_accounts a ON a.asset_id=s.id WHERE a.id=$1 AND a.deleted_at IS NULL AND s.deleted_at IS NULL FOR UPDATE OF s,a").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
   if before.get::<i64,_>("config_revision")!=revision{return Err(ErrorCode::RevisionConflict);}
   let protocol=parse(before.get("protocol"))?;let label=input.label.clone().unwrap_or_else(||before.get("label"));let username=input.username.clone().unwrap_or_else(||before.get("username"));let domain=input.domain.clone().unwrap_or_else(||before.get("domain"));let enabled=input.enabled.unwrap_or_else(||before.get("enabled"));
   let old:Option<Uuid>=before.get("credential_id");let existing_kind:Option<String>=if let Some(cid)=old{Some(sqlx::query_scalar("SELECT kind FROM credentials WHERE id=$1 FOR UPDATE").bind(cid).fetch_one(&mut *tx).await.map_err(db)?)}else{None};
   // Validation of unchanged secrets does not require decrypting them for a metadata edit.
   let placeholder=match existing_kind.as_deref(){Some("password")=>Credential::Password{password:"x".into()},Some("private_key")=>Credential::PrivateKey{key_pem:"x".into(),passphrase:None},_=>Credential::None};
    validate_account(protocol,&label,username.as_deref(),domain.as_deref(),input.credential.as_ref().unwrap_or(&placeholder))?;
    let credential=if let Some(value)=&input.credential{write_credential(self,&mut tx,old,value,keys).await?}else{old};
   let changed=input.credential.is_some() || username!=before.get::<Option<String>,_>("username") || domain!=before.get::<Option<String>,_>("domain") || enabled!=before.get::<bool,_>("enabled");
   sqlx::query("UPDATE target_accounts SET label=$3,username=$4,domain=$5,enabled=$6,credential_id=$7,config_revision=config_revision+1,security_revision=security_revision+CASE WHEN $8 THEN 1 ELSE 0 END WHERE id=$1 AND config_revision=$2").bind(id).bind(revision).bind(label).bind(username).bind(domain).bind(enabled).bind(credential).bind(changed).execute(&mut *tx).await.map_err(db)?;
   if old.is_some() && credential.is_none(){sqlx::query("DELETE FROM credentials WHERE id=$1").bind(old).execute(&mut *tx).await.map_err(db)?;}
   if changed {invalidate_account(&mut tx,id).await?;}audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"account.updated","account",Some(id),request_id,json!({"security_changed":changed})).await?;tx.commit().await.map_err(db)?;self.account(id).await
  }).await
    }
    pub async fn replace_credential(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        credential: CredentialInput,
        keys: &KeyRing,
        request_id: Uuid,
    ) -> StoreResult<AccountView> {
        self.update_account(
            actor,
            id,
            revision,
            &AccountUpdate {
                credential: Some(credential),
                ..Default::default()
            },
            keys,
            request_id,
        )
        .await
    }
    pub async fn create_grant(
        &self,
        actor: &Identity,
        user: Uuid,
        asset: Uuid,
        account: Uuid,
        expires: Option<DateTime<Utc>>,
        request_id: Uuid,
    ) -> StoreResult<GrantView> {
        bounded(async{let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;sqlx::query("SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE").bind(user).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;let row=sqlx::query("INSERT INTO grants(id,user_id,asset_id,account_id,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING *").bind(Uuid::new_v4()).bind(user).bind(asset).bind(account).bind(expires).fetch_one(&mut *tx).await.map_err(db)?;bump_policy(&mut tx).await?;audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"grant.created","grant",Some(row.get("id")),request_id,json!({"user_id":user,"asset_id":asset,"account_id":account})).await?;tx.commit().await.map_err(db)?;Ok(grant_view(&row))}).await
    }
    pub async fn grants(&self) -> StoreResult<Vec<GrantView>> {
        Ok(sqlx::query("SELECT * FROM grants ORDER BY id LIMIT 200")
            .fetch_all(&self.pool)
            .await
            .map_err(db)?
            .iter()
            .map(grant_view)
            .collect())
    }
    pub async fn grant(&self, id: Uuid) -> StoreResult<GrantView> {
        let row = sqlx::query("SELECT * FROM grants WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or(ErrorCode::ResourceNotFound)?;
        Ok(grant_view(&row))
    }
    pub async fn revoke_grant(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        request_id: Uuid,
    ) -> StoreResult<()> {
        self.update_grant(actor, id, revision, Some(false), None, request_id)
            .await
            .map(|_| ())
    }
    pub async fn update_grant(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        enabled: Option<bool>,
        expires: Option<Option<DateTime<Utc>>>,
        request_id: Uuid,
    ) -> StoreResult<GrantView> {
        if enabled.is_none() && expires.is_none() {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async{let mut tx=self.begin().await?;self.actor(&mut tx,actor,true).await?;let before=sqlx::query("SELECT u.deleted_at FROM users u JOIN grants g ON g.user_id=u.id WHERE g.id=$1 FOR UPDATE OF u,g").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;if before.get::<Option<DateTime<Utc>>,_>("deleted_at").is_some() && (enabled!=Some(false) || expires.is_some()) {return Err(ErrorCode::ResourceNotFound);}
   let row=sqlx::query("UPDATE grants SET enabled=COALESCE($3,enabled),expires_at=CASE WHEN $4 THEN $5 ELSE expires_at END,revision=revision+1 WHERE id=$1 AND revision=$2 RETURNING *").bind(id).bind(revision).bind(enabled).bind(expires.is_some()).bind(expires.flatten()).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::RevisionConflict)?;bump_policy(&mut tx).await?;invalidate_grant(&mut tx,&row).await?;audit(&mut tx,Some(actor.user.id),Some(actor.login_session_id),"grant.updated","grant",Some(id),request_id,json!({"enabled":enabled,"expires_at":expires})).await?;tx.commit().await.map_err(db)?;Ok(grant_view(&row))}).await
    }
    pub async fn assets_for(&self, identity: &Identity) -> StoreResult<serde_json::Value> {
        self.list_page(
            identity,
            Collection::Assets,
            PageRequest {
                limit: Some(200),
                ..Default::default()
            },
        )
        .await
    }
    pub async fn audit_events(&self, identity: &Identity) -> StoreResult<serde_json::Value> {
        self.list_page(
            identity,
            Collection::Audit,
            PageRequest {
                limit: Some(200),
                ..Default::default()
            },
        )
        .await
    }
}
async fn write_credential(
    store: &PgStore,
    tx: &mut Transaction<'_, Postgres>,
    existing: Option<Uuid>,
    value: &CredentialInput,
    keys: &KeyRing,
) -> StoreResult<Option<Uuid>> {
    if matches!(value, Credential::None) {
        return Ok(None);
    }
    let id = existing.unwrap_or_else(Uuid::new_v4);
    let revision = if existing.is_some() {
        sqlx::query_scalar::<_, i64>("SELECT revision+1 FROM credentials WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut **tx)
            .await
            .map_err(db)?
    } else {
        1
    };
    let context = CipherContext {
        server_id: store.server_id.to_string(),
        credential_id: id,
        kind: value.kind().into(),
        revision,
    };
    let e = keys
        .seal(&context, value)
        .map_err(|_| ErrorCode::InternalError)?;
    sqlx::query("INSERT INTO credentials(id,kind,revision,ciphertext,nonce,wrapped_dek,wrap_nonce,key_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET kind=EXCLUDED.kind,revision=EXCLUDED.revision,ciphertext=EXCLUDED.ciphertext,nonce=EXCLUDED.nonce,wrapped_dek=EXCLUDED.wrapped_dek,wrap_nonce=EXCLUDED.wrap_nonce,key_version=EXCLUDED.key_version").bind(id).bind(value.kind()).bind(revision).bind(e.ciphertext).bind(e.nonce).bind(e.wrapped_dek).bind(e.wrap_nonce).bind(e.key_version).execute(&mut **tx).await.map_err(db)?;
    Ok(Some(id))
}
pub(super) async fn bump_policy(tx: &mut Transaction<'_, Postgres>) -> StoreResult<()> {
    sqlx::query("UPDATE server_settings SET policy_revision=policy_revision+1 WHERE singleton")
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}
pub(super) async fn invalidate_asset(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> StoreResult<()> {
    sqlx::query(
        "UPDATE connection_tickets SET state='revoked' WHERE asset_id=$1 AND state='issued'",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    invalidate_pending(tx).await
}
async fn invalidate_account(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> StoreResult<()> {
    sqlx::query(
        "UPDATE connection_tickets SET state='revoked' WHERE account_id=$1 AND state='issued'",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    invalidate_pending(tx).await
}
async fn invalidate_pending(tx: &mut Transaction<'_, Postgres>) -> StoreResult<()> {
    sqlx::query("UPDATE connections c SET state='revoked',ended_at=clock_timestamp() FROM connection_tickets t WHERE c.ticket_id=t.id AND c.state='pending' AND t.state='revoked'").execute(&mut **tx).await.map_err(db)?;
    Ok(())
}

/// Push live sessions of a deleted resource into `closing`; the gateway closes them and records the end.
async fn close_connections(
    tx: &mut Transaction<'_, Postgres>,
    predicate: &str,
    id: Uuid,
) -> StoreResult<u64> {
    let sql = format!(
        "UPDATE connections SET state='closing' WHERE {predicate} AND state IN ('active','connecting')"
    );
    Ok(sqlx::query(&sql)
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(db)?
        .rows_affected())
}
async fn invalidate_grant(tx: &mut Transaction<'_, Postgres>, row: &PgRow) -> StoreResult<()> {
    sqlx::query("UPDATE connection_tickets SET state='revoked' WHERE user_id=$1 AND asset_id=$2 AND account_id=$3 AND state='issued' AND EXISTS(SELECT 1 FROM users u WHERE u.id=$1 AND u.role<>'admin') AND NOT EXISTS(SELECT 1 FROM grants g WHERE g.user_id=$1 AND g.asset_id=$2 AND g.account_id=$3 AND g.enabled AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()))").bind(row.get::<Uuid,_>("user_id")).bind(row.get::<Uuid,_>("asset_id")).bind(row.get::<Uuid,_>("account_id")).execute(&mut **tx).await.map_err(db)?;
    invalidate_pending(tx).await
}

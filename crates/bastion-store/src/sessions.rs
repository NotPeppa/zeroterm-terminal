use crate::{postgres::*, targets::*, *};
use bastion_domain::*;
use bastion_secrets::{hash, matches_hash, CipherContext, Envelope, Secret};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
pub(super) struct Binding {
    pub user: UserView,
    pub asset: AssetView,
    pub account_revision: i64,
    pub credential_revision: Option<i64>,
    pub username: Option<String>,
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
        let row=sqlx::query("SELECT u.*,s.id AS session_id,s.revoked_at,s.expires_at>clock_timestamp() AS session_valid,true AS token_valid FROM users u JOIN login_sessions s ON s.user_id=u.id WHERE u.id=$1 AND s.id=$2 FOR UPDATE OF u,s").bind(user).bind(session).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(ErrorCode::Unauthenticated)?;
        let identity = identity_from_row(&row)?;
        if identity.user.role == Role::Auditor {
            return Err(ErrorCode::PermissionDenied);
        }
        let row=sqlx::query("SELECT a.*,t.username,t.security_revision AS account_revision,t.enabled AS account_enabled,t.credential_id FROM assets a JOIN target_accounts t ON t.asset_id=a.id WHERE a.id=$1 AND t.id=$2 AND a.deleted_at IS NULL AND t.deleted_at IS NULL FOR UPDATE OF a,t").bind(asset).bind(account).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(ErrorCode::PermissionDenied)?;
        if !row.get::<bool, _>("enabled") || !row.get::<bool, _>("account_enabled") {
            return Err(ErrorCode::PermissionDenied);
        }
        if identity.user.role!=Role::Admin && !sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM grants g WHERE g.user_id=$1 AND g.asset_id=$2 AND g.account_id=$3 AND g.enabled AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()))").bind(user).bind(asset).bind(account).fetch_one(&mut **tx).await.map_err(db)? {return Err(ErrorCode::PermissionDenied);}
        let unconfirmed = match row.get::<String, _>("protocol").as_str() {
            "ssh" => row.get::<Option<String>, _>("ssh_host_key").is_none(),
            "rdp" => row
                .get::<Option<String>, _>("rdp_certificate_sha256")
                .is_none(),
            _ => false,
        };
        if unconfirmed {
            return Err(ErrorCode::TargetHostKeyUnknown);
        }
        let credential_revision = if let Some(id) = row.get::<Option<Uuid>, _>("credential_id") {
            Some(
                sqlx::query_scalar("SELECT revision FROM credentials WHERE id=$1 FOR UPDATE")
                    .bind(id)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(db)?,
            )
        } else {
            None
        };
        Ok(Binding {
            user: identity.user,
            asset: asset_view(&row)?,
            account_revision: row.get("account_revision"),
            credential_revision,
            username: row.get("username"),
        })
    }
    pub async fn issue_web_session(
        &self,
        identity: &Identity,
        request: SessionRequest,
        request_id: Uuid,
    ) -> StoreResult<WebSessionResponse> {
        request.display.validate()?;
        bounded(async {let mut tx=self.begin().await?;self.actor(&mut tx,identity,false).await?;expire_tickets(&mut tx).await?;let binding=self.binding(&mut tx,identity.user.id,identity.login_session_id,request.asset_id,request.account_id).await?;
   let count:i64=sqlx::query_scalar("SELECT count(*) FROM connection_tickets WHERE user_id=$1 AND state='issued' AND expires_at>clock_timestamp()").bind(identity.user.id).fetch_one(&mut *tx).await.map_err(db)?;if count>=self.session_limits()?[2]{return Err(ErrorCode::ConnectionLimit);}connection_limits(&mut tx,identity.user.id,self.session_limits()?).await?;
   let ticket=Uuid::new_v4();let connection=Uuid::new_v4();let secret=Secret::random();let expiry:DateTime<Utc>=sqlx::query_scalar("INSERT INTO connection_tickets(id,secret_hash,connection_id,user_id,login_session_id,asset_id,account_id,gateway_id,auth_revision,routing_revision,account_revision,credential_revision,state,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'issued',clock_timestamp()+interval '30 seconds') RETURNING expires_at").bind(ticket).bind(secret.hash().as_slice()).bind(connection).bind(identity.user.id).bind(identity.login_session_id).bind(request.asset_id).bind(request.account_id).bind(self.gateway_id.as_ref()).bind(binding.user.revision).bind(binding.asset.routing_revision).bind(binding.account_revision).bind(binding.credential_revision).fetch_one(&mut *tx).await.map_err(db)?;
   sqlx::query("INSERT INTO connections(id,ticket_id,user_id,login_session_id,asset_id,account_id,state,gateway_id,auth_revision,routing_revision,account_revision,credential_revision,target_host,target_port,target_username,user_snapshot,asset_snapshot,target_protocol,width,height,dpi) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)").bind(connection).bind(ticket).bind(identity.user.id).bind(identity.login_session_id).bind(request.asset_id).bind(request.account_id).bind(self.gateway_id.as_ref()).bind(binding.user.revision).bind(binding.asset.routing_revision).bind(binding.account_revision).bind(binding.credential_revision).bind(&binding.asset.host).bind(binding.asset.port).bind(&binding.username).bind(&binding.user.username).bind(&binding.asset.name).bind(binding.asset.protocol.as_str()).bind(request.display.width as i32).bind(request.display.height as i32).bind(request.display.dpi as i32).execute(&mut *tx).await.map_err(db)?;
   audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"ticket.issued","connection",Some(connection),request_id,json!({"asset_id":request.asset_id,"account_id":request.account_id,"target_protocol":binding.asset.protocol})).await?;tx.commit().await.map_err(db)?;Ok(WebSessionResponse{session_id:ticket,ws_token:secret.expose().into(),connection_id:connection,expires_at:expiry,target_protocol:binding.asset.protocol,stream_protocol:binding.asset.protocol.stream_protocol()})
  }).await
    }
    pub async fn consume_web_session(
        &self,
        id: Uuid,
        secret: &str,
        identity: &Identity,
    ) -> StoreResult<Connection> {
        self.consume_web_session_with_stream(id, secret, identity, None)
            .await
    }
    pub async fn consume_web_session_with_stream(
        &self,
        id: Uuid,
        secret: &str,
        identity: &Identity,
        stream_protocol: Option<&str>,
    ) -> StoreResult<Connection> {
        bounded(async {let mut tx=self.begin().await?;
   let route=sqlx::query("SELECT t.*,c.target_protocol FROM connection_tickets t JOIN connections c ON c.id=t.connection_id WHERE t.id=$1").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::TicketInvalid)?;
   // Check secret AND owner/login before any state-changing rejection. Wrong callers cannot burn a ticket.
   let expected:[u8;32]=route.get::<Vec<u8>,_>("secret_hash").try_into().map_err(|_|ErrorCode::InternalError)?;
   if identity.user.id!=route.get::<Uuid,_>("user_id") || identity.login_session_id!=route.get::<Uuid,_>("login_session_id") || !matches_hash(&expected,secret){return Err(ErrorCode::TicketInvalid);}
   let protocol:TargetProtocol=parse(route.get("target_protocol"))?;
   if stream_protocol.is_some_and(|value| value!=protocol.stream_protocol()){return Err(ErrorCode::TicketInvalid);}
   // Establish parent-row lock order before locking the ticket. The actual rejection is checked below.
   let _=self.binding(&mut tx,identity.user.id,identity.login_session_id,route.get("asset_id"),route.get("account_id")).await;
   let ticket=sqlx::query("SELECT * FROM connection_tickets WHERE id=$1 FOR UPDATE").bind(id).fetch_one(&mut *tx).await.map_err(db)?;
   match ticket.get::<String,_>("state").as_str(){"issued"=>{},"expired"=>return Err(ErrorCode::TicketExpired),"revoked"=>return Err(ErrorCode::TicketStale),_=>return Err(ErrorCode::TicketUsed)};
   let cid:Uuid=ticket.get("connection_id");let row=sqlx::query("SELECT * FROM connections WHERE id=$1 AND ticket_id=$2 AND state='pending' FOR UPDATE").bind(cid).bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::TicketInvalid)?;let connection=connection_view(&row)?;
   let binding=self.binding(&mut tx,identity.user.id,identity.login_session_id,connection.asset_id,connection.account_id).await;
   let valid:bool=sqlx::query_scalar("SELECT expires_at>clock_timestamp() FROM connection_tickets WHERE id=$1").bind(id).fetch_one(&mut *tx).await.map_err(db)?;
   let reason=if !valid{Some(ErrorCode::TicketExpired)}else{match binding {Err(code)=>Some(code),Ok(ref b)=>{if identity.user.revision!=b.user.revision{Some(ErrorCode::LoginSessionRevoked)}else if ticket.get::<String,_>("gateway_id")!=self.gateway_id.as_ref() || !bound(&connection,b) || ticket.get::<i64,_>("auth_revision")!=b.user.revision || ticket.get::<i64,_>("routing_revision")!=b.asset.routing_revision || ticket.get::<i64,_>("account_revision")!=b.account_revision || ticket.get::<Option<i64>,_>("credential_revision")!=b.credential_revision {Some(ErrorCode::TicketStale)}else{None}}}};
   if let Some(code)=reason{let state=if code==ErrorCode::TicketExpired{"expired"}else{"revoked"};sqlx::query("UPDATE connection_tickets SET state=$2 WHERE id=$1").bind(id).bind(state).execute(&mut *tx).await.map_err(db)?;sqlx::query("UPDATE connections SET state=$2,ended_at=clock_timestamp(),failure_code=$3 WHERE id=$1").bind(cid).bind(state).bind(code_string(code)).execute(&mut *tx).await.map_err(db)?;audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"ticket.rejected","connection",Some(cid),Uuid::new_v4(),json!({"reason_code":code})).await?;tx.commit().await.map_err(db)?;return Err(code);}
   connection_limits(&mut tx,identity.user.id,self.session_limits()?).await?;let changed=sqlx::query("UPDATE connection_tickets SET state='consumed',consumed_at=clock_timestamp() WHERE id=$1 AND secret_hash=$2 AND state='issued' AND expires_at>clock_timestamp()").bind(id).bind(hash(secret).as_slice()).execute(&mut *tx).await.map_err(db)?;if changed.rows_affected()!=1{return Err(ErrorCode::TicketExpired);}
   let row=sqlx::query("UPDATE connections SET state='connecting',started_at=clock_timestamp() WHERE id=$1 AND state='pending' RETURNING *").bind(cid).fetch_one(&mut *tx).await.map_err(db)?;audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"ticket.consumed","connection",Some(cid),Uuid::new_v4(),json!({})).await?;tx.commit().await.map_err(db)?;connection_view(&row)
  }).await
    }
    pub(super) async fn runtime_connection(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> StoreResult<Connection> {
        let row = sqlx::query("SELECT * FROM connections WHERE id=$1")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .ok_or(ErrorCode::ResourceNotFound)?;
        let route = connection_view(&row)?;
        let user = route.user_id.ok_or(ErrorCode::Unauthenticated)?;
        let login = route.login_session_id.ok_or(ErrorCode::Unauthenticated)?;
        self.binding(tx, user, login, route.asset_id, route.account_id)
            .await?;
        let row = sqlx::query("SELECT * FROM connections WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut **tx)
            .await
            .map_err(db)?;
        let current = connection_view(&row)?;
        let binding = self
            .binding(tx, user, login, current.asset_id, current.account_id)
            .await?;
        if !matches!(
            current.state,
            ConnectionState::Connecting | ConnectionState::Active
        ) || !bound(&current, &binding)
        {
            return Err(ErrorCode::TicketStale);
        }
        Ok(current)
    }
    pub async fn authorize_connection(&self, connection: &Connection) -> StoreResult<()> {
        bounded(async {
            let mut tx = self.begin().await?;
            let current = self.runtime_connection(&mut tx, connection.id).await?;
            if !same_binding(connection, &current) {
                return Err(ErrorCode::TicketStale);
            }
            tx.commit().await.map_err(db)
        })
        .await
    }
    pub async fn target_snapshot(&self, connection: &Connection) -> StoreResult<TargetSnapshot> {
        bounded(async{let mut tx=self.begin().await?;let current=self.runtime_connection(&mut tx,connection.id).await?;if !same_binding(connection,&current){return Err(ErrorCode::TicketStale);}
   let row=sqlx::query("SELECT a.host,a.port,a.protocol,a.security,a.ssh_host_key,a.rdp_certificate_sha256,t.username,t.domain,c.id AS credential_id,c.kind,c.revision AS credential_revision,c.ciphertext,c.nonce,c.wrapped_dek,c.wrap_nonce,c.key_version FROM assets a JOIN target_accounts t ON t.asset_id=a.id LEFT JOIN credentials c ON c.id=t.credential_id WHERE a.id=$1 AND t.id=$2").bind(connection.asset_id).bind(connection.account_id).fetch_one(&mut *tx).await.map_err(db)?;
   let cid:Option<Uuid>=row.get("credential_id");let snapshot=TargetSnapshot{host:row.get("host"),port:row.get::<i32,_>("port") as u16,protocol:parse(row.get("protocol"))?,security:row.get::<Option<String>,_>("security").map(parse).transpose()?,ssh_host_key:row.get("ssh_host_key"),rdp_certificate_sha256:row.get("rdp_certificate_sha256"),username:row.get("username"),domain:row.get("domain"),context:cid.map(|credential_id|CipherContext{server_id:self.server_id.to_string(),credential_id,kind:row.get("kind"),revision:row.get("credential_revision")}),credential:cid.map(|_|Envelope{ciphertext:row.get("ciphertext"),nonce:row.get("nonce"),wrapped_dek:row.get("wrapped_dek"),wrap_nonce:row.get("wrap_nonce"),key_version:row.get("key_version")})};tx.commit().await.map_err(db)?;Ok(snapshot)
  }).await
    }
}
fn bound(c: &Connection, b: &Binding) -> bool {
    c.auth_revision == b.user.revision
        && c.routing_revision == b.asset.routing_revision
        && c.account_revision == b.account_revision
        && c.credential_revision == b.credential_revision
        && c.target_protocol == b.asset.protocol
}
fn same_binding(a: &Connection, b: &Connection) -> bool {
    a.ticket_id == b.ticket_id
        && a.asset_id == b.asset_id
        && a.account_id == b.account_id
        && a.user_id == b.user_id
        && a.login_session_id == b.login_session_id
        && a.auth_revision == b.auth_revision
        && a.routing_revision == b.routing_revision
        && a.account_revision == b.account_revision
        && a.credential_revision == b.credential_revision
        && a.target_protocol == b.target_protocol
        && a.display == b.display
}
async fn connection_limits(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    limits: [i64; 3],
) -> StoreResult<()> {
    let row=sqlx::query("SELECT count(*) AS total,count(*) FILTER(WHERE user_id=$1) AS per_user FROM connections WHERE state IN ('connecting','active','closing')").bind(user).fetch_one(&mut **tx).await.map_err(db)?;
    if row.get::<i64, _>("total") >= limits[0] || row.get::<i64, _>("per_user") >= limits[1] {
        Err(ErrorCode::ConnectionLimit)
    } else {
        Ok(())
    }
}

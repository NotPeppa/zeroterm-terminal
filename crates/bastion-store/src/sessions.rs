use crate::{postgres::*, targets::*, *};
use bastion_domain::*;
use bastion_secrets::{hash, matches_hash, CipherContext, Envelope, Secret};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
struct Issued {
    ticket: Uuid,
    secret: Secret,
    connection: Uuid,
    expires_at: DateTime<Utc>,
    protocol: TargetProtocol,
}
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
        client: ClientType,
    ) -> StoreResult<Binding> {
        let row=sqlx::query("SELECT u.*,s.id AS session_id,s.revoked_at,s.expires_at>clock_timestamp() AS session_valid,true AS token_valid,s.client_type FROM users u JOIN login_sessions s ON s.user_id=u.id WHERE u.id=$1 AND s.id=$2 FOR UPDATE OF u,s").bind(user).bind(session).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(ErrorCode::Unauthenticated)?;
        let identity = identity_from_row(&row)?;
        // A browser login never issues, consumes or keeps a native connection, and vice versa.
        if row.get::<String, _>("client_type") != client.as_str() {
            return Err(ErrorCode::Unauthenticated);
        }
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
        let issued = self
            .issue_ticket(
                identity,
                request.asset_id,
                request.account_id,
                Transport::Websocket,
                Some(request.display),
                None,
                request_id,
            )
            .await?;
        Ok(WebSessionResponse {
            session_id: issued.ticket,
            ws_token: issued.secret.expose().into(),
            connection_id: issued.connection,
            expires_at: issued.expires_at,
            target_protocol: issued.protocol,
            stream_protocol: issued.protocol.stream_protocol(),
        })
    }
    /// RFC-006 §4.1: SSH assets only, N1 capabilities only, same limits and revision freeze as the browser.
    pub async fn issue_native_ticket(
        &self,
        identity: &Identity,
        request: NativeTicketRequest,
        request_id: Uuid,
    ) -> StoreResult<NativeTicketIssued> {
        validate_native_capabilities(&request.capabilities)?;
        let issued = self
            .issue_ticket(
                identity,
                request.asset_id,
                request.account_id,
                Transport::NativeSsh,
                None,
                Some(&request.capabilities),
                request_id,
            )
            .await?;
        Ok(NativeTicketIssued {
            ticket_id: issued.ticket,
            ticket_secret: issued.secret.expose().into(),
            connection_id: issued.connection,
            capabilities: request.capabilities,
            expires_at: issued.expires_at,
        })
    }
    /// The one issuance transaction behind both entries: binding, pending and connection ceilings
    /// (counted across transports), revision snapshot and `ticket.issued` audit.
    #[allow(clippy::too_many_arguments)]
    async fn issue_ticket(
        &self,
        identity: &Identity,
        asset_id: Uuid,
        account_id: Uuid,
        transport: Transport,
        display: Option<Display>,
        capabilities: Option<&[String]>,
        request_id: Uuid,
    ) -> StoreResult<Issued> {
        bounded(async {let mut tx=self.begin().await?;self.actor(&mut tx,identity,false).await?;expire_tickets(&mut tx).await?;
   // Protocol is immutable, so this precheck cannot race; non-SSH assets are simply not native targets.
   if transport==Transport::NativeSsh && sqlx::query_scalar::<_,String>("SELECT protocol FROM assets WHERE id=$1").bind(asset_id).fetch_optional(&mut *tx).await.map_err(db)?.as_deref()!=Some("ssh"){return Err(ErrorCode::PermissionDenied);}
   let binding=self.binding(&mut tx,identity.user.id,identity.login_session_id,asset_id,account_id,transport.client_type()).await?;
   let count:i64=sqlx::query_scalar("SELECT count(*) FROM connection_tickets WHERE user_id=$1 AND state='issued' AND expires_at>clock_timestamp()").bind(identity.user.id).fetch_one(&mut *tx).await.map_err(db)?;if count>=self.session_limits()?[2]{return Err(ErrorCode::ConnectionLimit);}connection_limits(&mut tx,identity.user.id,self.session_limits()?).await?;
   let ticket=Uuid::new_v4();let connection=Uuid::new_v4();let secret=Secret::random();let expiry:DateTime<Utc>=sqlx::query_scalar("INSERT INTO connection_tickets(id,secret_hash,connection_id,user_id,login_session_id,asset_id,account_id,gateway_id,auth_revision,routing_revision,account_revision,credential_revision,state,expires_at,transport,capabilities) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'issued',clock_timestamp()+interval '30 seconds',$13,$14) RETURNING expires_at").bind(ticket).bind(secret.hash().as_slice()).bind(connection).bind(identity.user.id).bind(identity.login_session_id).bind(asset_id).bind(account_id).bind(self.gateway_id.as_ref()).bind(binding.user.revision).bind(binding.asset.routing_revision).bind(binding.account_revision).bind(binding.credential_revision).bind(transport.as_str()).bind(capabilities).fetch_one(&mut *tx).await.map_err(db)?;
   sqlx::query("INSERT INTO connections(id,ticket_id,user_id,login_session_id,asset_id,account_id,state,gateway_id,auth_revision,routing_revision,account_revision,credential_revision,target_host,target_port,target_username,user_snapshot,asset_snapshot,target_protocol,width,height,dpi,client_ip,transport) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21::inet,$22)").bind(connection).bind(ticket).bind(identity.user.id).bind(identity.login_session_id).bind(asset_id).bind(account_id).bind(self.gateway_id.as_ref()).bind(binding.user.revision).bind(binding.asset.routing_revision).bind(binding.account_revision).bind(binding.credential_revision).bind(&binding.asset.host).bind(binding.asset.port).bind(&binding.username).bind(&binding.user.username).bind(&binding.asset.name).bind(binding.asset.protocol.as_str()).bind(display.map(|d|d.width as i32)).bind(display.map(|d|d.height as i32)).bind(display.map(|d|d.dpi as i32)).bind(crate::postgres::client_ip()).bind(transport.as_str()).execute(&mut *tx).await.map_err(db)?;
   let mut payload=json!({"asset_id":asset_id,"account_id":account_id,"target_protocol":binding.asset.protocol,"transport":transport});if let Some(capabilities)=capabilities{payload["capabilities"]=json!(capabilities);}
   audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"ticket.issued","connection",Some(connection),request_id,payload).await?;tx.commit().await.map_err(db)?;Ok(Issued{ticket,secret,connection,expires_at:expiry,protocol:binding.asset.protocol})
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
        self.consume_ticket(
            id,
            secret,
            Some(identity),
            stream_protocol,
            Transport::Websocket,
        )
        .await
        .map(|(connection, _)| connection)
    }
    /// SSH gateway `auth_password` for `zt1:<ticket_id>`. There is no cookie identity: user and login
    /// come from the ticket row, then every browser consumption check applies plus `client_type=native`
    /// and `transport=native_ssh`. A wrong secret or transport never changes ticket state. Audit rows
    /// written here carry `peer_ip`. Returns the connecting connection and the ticket's capabilities.
    pub async fn consume_native_ticket(
        &self,
        id: Uuid,
        secret: &str,
        peer_ip: std::net::IpAddr,
    ) -> StoreResult<NativeSession> {
        crate::postgres::CLIENT_IP
            .scope(peer_ip, async {
                let (connection, capabilities) = self
                    .consume_ticket(id, secret, None, None, Transport::NativeSsh)
                    .await?;
                Ok(NativeSession {
                    connection,
                    capabilities,
                })
            })
            .await
    }
    /// Failed native password attempts (unknown ticket, wrong secret) leave no ticket change; the
    /// gateway records the source address here. Only the ticket id is kept, never the secret.
    pub async fn native_auth_failure(
        &self,
        peer_ip: std::net::IpAddr,
        ticket: Option<Uuid>,
        reason: ErrorCode,
    ) -> StoreResult<()> {
        crate::postgres::CLIENT_IP
            .scope(peer_ip, bounded(async {
                let mut tx = self.begin().await?;
                audit(&mut tx, None, None, "native.auth_failure", "connection", None, Uuid::new_v4(), json!({"reason_code":reason,"ticket_id":ticket,"transport":Transport::NativeSsh})).await?;
                tx.commit().await.map_err(db)
            }))
            .await
    }
    /// `connecting → active` for a native connection whose first accepted channel carries no
    /// recording (exec/sftp only, RFC-006 §14.2). Same authorization, revision and audit as
    /// `activate_recording`; a connection that is already active is left as is. Browser
    /// connections always activate through their recording and are refused here.
    pub async fn activate_native_connection(&self, connection: &Connection) -> StoreResult<()> {
        if connection.transport != Transport::NativeSsh {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async {
            let mut tx = self.begin().await?;
            let current = self.runtime_connection(&mut tx, connection.id).await?;
            if current.transport != Transport::NativeSsh {
                return Err(ErrorCode::InvalidArgument);
            }
            if !same_binding(connection, &current) {
                return Err(ErrorCode::TicketStale);
            }
            if current.state == ConnectionState::Connecting {
                sqlx::query(
                    "UPDATE connections SET state='active' WHERE id=$1 AND state='connecting'",
                )
                .bind(current.id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                audit(
                    &mut tx,
                    current.user_id,
                    current.login_session_id,
                    "connection.active",
                    "connection",
                    Some(current.id),
                    Uuid::new_v4(),
                    json!({"recording_id":null,"transport":Transport::NativeSsh}),
                )
                .await?;
            }
            tx.commit().await.map_err(db)
        })
        .await
    }
    /// One finished native `exec` channel (RFC-006 §14.3, `exec.completed`). Only the command and
    /// counters are kept; output is never recorded.
    pub async fn exec_completed(
        &self,
        connection: &Connection,
        command: &[u8],
        outcome: &ExecOutcome,
    ) -> StoreResult<()> {
        let mut payload = exec_command(connection.id, command);
        payload["exit_status"] = json!(outcome.exit_status);
        payload["exit_signal"] = json!(outcome
            .exit_signal
            .as_deref()
            .map(|name| audit_text(name, 64)));
        payload["stdin_bytes"] = json!(outcome.stdin_bytes);
        payload["stdout_bytes"] = json!(outcome.stdout_bytes);
        payload["stderr_bytes"] = json!(outcome.stderr_bytes);
        payload["duration_ms"] = json!(outcome.duration_ms);
        self.exec_audit(connection, "exec.completed", payload).await
    }
    /// A native `exec` request refused before the target ran it (`exec.rejected`).
    pub async fn exec_rejected(
        &self,
        connection: &Connection,
        command: &[u8],
        reason: ErrorCode,
    ) -> StoreResult<()> {
        let mut payload = exec_command(connection.id, command);
        payload["reason_code"] = json!(reason);
        self.exec_audit(connection, "exec.rejected", payload).await
    }
    pub async fn sftp_audit(&self, connection: &Connection, entry: &SftpAudit) -> StoreResult<()> {
        let (action, payload) = sftp_payload(connection.id, entry);
        self.exec_audit(connection, action, payload).await
    }
    pub async fn sftp_rejected(
        &self,
        connection: &Connection,
        reason: ErrorCode,
    ) -> StoreResult<()> {
        self.exec_audit(
            connection,
            "sftp.rejected",
            json!({"connection_id":connection.id,
            "transport":Transport::NativeSsh,"reason_code":reason}),
        )
        .await
    }
    async fn exec_audit(
        &self,
        connection: &Connection,
        action: &str,
        payload: serde_json::Value,
    ) -> StoreResult<()> {
        if connection.transport != Transport::NativeSsh {
            return Err(ErrorCode::InvalidArgument);
        }
        let written = bounded(async {
            let mut tx = self.begin().await?;
            // Actor columns come from the row, which may have lost its user since the gateway read it.
            let row = sqlx::query(
                "SELECT user_id,login_session_id,transport FROM connections WHERE id=$1 FOR UPDATE",
            )
            .bind(connection.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(ErrorCode::ResourceNotFound)?;
            if row.get::<String, _>("transport") != Transport::NativeSsh.as_str() {
                return Err(ErrorCode::InvalidArgument);
            }
            audit(
                &mut tx,
                row.get("user_id"),
                row.get("login_session_id"),
                action,
                "connection",
                Some(connection.id),
                Uuid::new_v4(),
                payload,
            )
            .await?;
            tx.commit().await.map_err(db)
        })
        .await;
        if let Err(code) = written {
            tracing::error!(connection = %connection.id, action, ?code, "native channel audit not recorded");
        }
        written
    }
    async fn consume_ticket(
        &self,
        id: Uuid,
        secret: &str,
        caller: Option<&Identity>,
        stream_protocol: Option<&str>,
        transport: Transport,
    ) -> StoreResult<(Connection, Vec<String>)> {
        bounded(async {let mut tx=self.begin().await?;
   let route=sqlx::query("SELECT t.*,c.target_protocol FROM connection_tickets t JOIN connections c ON c.id=t.connection_id WHERE t.id=$1").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::TicketInvalid)?;
   // Check secret, transport AND owner/login before any state-changing rejection. Wrong callers cannot burn a ticket.
   let expected:[u8;32]=route.get::<Vec<u8>,_>("secret_hash").try_into().map_err(|_|ErrorCode::InternalError)?;
   if !matches_hash(&expected,secret) || route.get::<String,_>("transport")!=transport.as_str() || caller.is_some_and(|who| who.user.id!=route.get::<Uuid,_>("user_id") || who.login_session_id!=route.get::<Uuid,_>("login_session_id")){return Err(ErrorCode::TicketInvalid);}
   let (user,login):(Uuid,Uuid)=(route.get("user_id"),route.get("login_session_id"));let client=transport.client_type();
   let protocol:TargetProtocol=parse(route.get("target_protocol"))?;
   if stream_protocol.is_some_and(|value| value!=protocol.stream_protocol()){return Err(ErrorCode::TicketInvalid);}
   // Establish parent-row lock order before locking the ticket. The actual rejection is checked below.
   let _=self.binding(&mut tx,user,login,route.get("asset_id"),route.get("account_id"),client).await;
   let ticket=sqlx::query("SELECT * FROM connection_tickets WHERE id=$1 FOR UPDATE").bind(id).fetch_one(&mut *tx).await.map_err(db)?;
   match ticket.get::<String,_>("state").as_str(){"issued"=>{},"expired"=>return Err(ErrorCode::TicketExpired),"revoked"=>return Err(ErrorCode::TicketStale),_=>return Err(ErrorCode::TicketUsed)};
   let cid:Uuid=ticket.get("connection_id");let row=sqlx::query("SELECT * FROM connections WHERE id=$1 AND ticket_id=$2 AND state='pending' FOR UPDATE").bind(cid).bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::TicketInvalid)?;let connection=connection_view(&row)?;
   let binding=self.binding(&mut tx,user,login,connection.asset_id,connection.account_id,client).await;
   let valid:bool=sqlx::query_scalar("SELECT expires_at>clock_timestamp() FROM connection_tickets WHERE id=$1").bind(id).fetch_one(&mut *tx).await.map_err(db)?;
   let reason=if !valid{Some(ErrorCode::TicketExpired)}else{match binding {Err(code)=>Some(code),Ok(ref b)=>{if caller.is_some_and(|who| who.user.revision!=b.user.revision){Some(ErrorCode::LoginSessionRevoked)}else if ticket.get::<String,_>("gateway_id")!=self.gateway_id.as_ref() || connection.transport!=transport || !bound(&connection,b) || ticket.get::<i64,_>("auth_revision")!=b.user.revision || ticket.get::<i64,_>("routing_revision")!=b.asset.routing_revision || ticket.get::<i64,_>("account_revision")!=b.account_revision || ticket.get::<Option<i64>,_>("credential_revision")!=b.credential_revision {Some(ErrorCode::TicketStale)}else{None}}}};
   if let Some(code)=reason{let state=if code==ErrorCode::TicketExpired{"expired"}else{"revoked"};sqlx::query("UPDATE connection_tickets SET state=$2 WHERE id=$1").bind(id).bind(state).execute(&mut *tx).await.map_err(db)?;sqlx::query("UPDATE connections SET state=$2,ended_at=clock_timestamp(),failure_code=$3 WHERE id=$1").bind(cid).bind(state).bind(code_string(code)).execute(&mut *tx).await.map_err(db)?;audit(&mut tx,Some(user),Some(login),"ticket.rejected","connection",Some(cid),Uuid::new_v4(),json!({"reason_code":code,"transport":transport})).await?;tx.commit().await.map_err(db)?;return Err(code);}
   connection_limits(&mut tx,user,self.session_limits()?).await?;let changed=sqlx::query("UPDATE connection_tickets SET state='consumed',consumed_at=clock_timestamp() WHERE id=$1 AND secret_hash=$2 AND state='issued' AND expires_at>clock_timestamp()").bind(id).bind(hash(secret).as_slice()).execute(&mut *tx).await.map_err(db)?;if changed.rows_affected()!=1{return Err(ErrorCode::TicketExpired);}
   let row=sqlx::query("UPDATE connections SET state='connecting',started_at=clock_timestamp() WHERE id=$1 AND state='pending' RETURNING *").bind(cid).fetch_one(&mut *tx).await.map_err(db)?;audit(&mut tx,Some(user),Some(login),"ticket.consumed","connection",Some(cid),Uuid::new_v4(),json!({"transport":transport})).await?;tx.commit().await.map_err(db)?;
   Ok((connection_view(&row)?,ticket.get::<Option<Vec<String>>,_>("capabilities").unwrap_or_default()))
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
        self.binding(
            tx,
            user,
            login,
            route.asset_id,
            route.account_id,
            route.transport.client_type(),
        )
        .await?;
        let row = sqlx::query("SELECT * FROM connections WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut **tx)
            .await
            .map_err(db)?;
        let current = connection_view(&row)?;
        let binding = self
            .binding(
                tx,
                user,
                login,
                current.asset_id,
                current.account_id,
                current.transport.client_type(),
            )
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
        && a.transport == b.transport
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
/// Bytes of an exec command kept as readable text in its audit row (RFC-006 §14.3).
fn sftp_payload(connection: Uuid, entry: &SftpAudit) -> (&'static str, serde_json::Value) {
    let path_text = |bytes: &[u8]| audit_text(&String::from_utf8_lossy(bytes), 4096);
    let (action, mut payload) = match entry {
        SftpAudit::Operation {
            op,
            path,
            target_path,
            status,
        } => (
            op.as_action(),
            json!({"path":path_text(path),
            "target_path":target_path.as_deref().map(path_text),"status":status}),
        ),
        SftpAudit::File {
            path,
            flags,
            status,
            read_bytes,
            write_bytes,
            sha256,
            read_sha256,
            write_sha256,
        } => (
            "sftp.file",
            json!({"path":path_text(path),"flags":flags,"status":status,"read_bytes":read_bytes,
                "write_bytes":write_bytes,"sha256":sha256,"read_sha256":read_sha256,"write_sha256":write_sha256}),
        ),
        SftpAudit::Session {
            requests,
            input_bytes,
            output_bytes,
        } => (
            "sftp.session",
            json!({"requests":requests,
            "input_bytes":input_bytes,"output_bytes":output_bytes}),
        ),
    };
    payload["connection_id"] = json!(connection);
    payload["transport"] = json!(Transport::NativeSsh);
    (action, payload)
}

pub const EXEC_AUDIT_PREVIEW_BYTES: usize = 4096;
/// Command fields shared by `exec.completed` and `exec.rejected`: a lossy UTF-8 preview of the first
/// 4 KiB, and the SHA-256 of the full bytes so a truncated or non-UTF-8 command is still identifiable.
fn exec_command(connection: Uuid, command: &[u8]) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let truncated = command.len() > EXEC_AUDIT_PREVIEW_BYTES;
    let preview = &command[..command.len().min(EXEC_AUDIT_PREVIEW_BYTES)];
    let sha256: String = Sha256::digest(command)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({
        "connection_id": connection,
        "transport": Transport::NativeSsh,
        "command": audit_text(&String::from_utf8_lossy(preview), EXEC_AUDIT_PREVIEW_BYTES),
        "command_sha256": sha256,
        "command_bytes": command.len(),
        "truncated": truncated,
    })
}
/// jsonb cannot hold U+0000, so NUL is shown as the replacement character like other invalid bytes.
fn audit_text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .take(max_chars)
        .map(|c| {
            if c == '\0' {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            }
        })
        .collect()
}
#[cfg(test)]
mod exec_audit_tests {
    use super::*;
    #[test]
    fn exec_command_preview_is_bounded_lossy_and_hashes_the_full_command() {
        let short = exec_command(Uuid::nil(), b"uptime");
        assert_eq!(short["command"], "uptime");
        assert_eq!(short["truncated"], false);
        assert_eq!(short["command_bytes"], 6);
        assert_eq!(
            short["command_sha256"],
            "dd291cd6294bafef2a7e9c378eb320e87198d6dae214272addb569775750c802"
        );
        let mut long = vec![b'a'; EXEC_AUDIT_PREVIEW_BYTES + 10];
        long[0] = 0xff;
        long[1] = 0;
        let long = exec_command(Uuid::nil(), &long);
        let preview = long["command"].as_str().unwrap();
        assert!(preview.starts_with("\u{fffd}\u{fffd}aaa"), "{preview:?}");
        assert!(!preview.contains('\0'));
        assert_eq!(long["truncated"], true);
        assert_eq!(long["command_bytes"], EXEC_AUDIT_PREVIEW_BYTES + 10);
        assert_eq!(long["command_sha256"].as_str().unwrap().len(), 64);
    }
}

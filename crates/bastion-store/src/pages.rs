use crate::{PgStore, StoreResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bastion_domain::{ErrorCode, Identity, Role};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Cursor {
    scope: String,
    time: DateTime<Utc>,
    id: Uuid,
}
#[derive(Clone, Copy, Debug)]
pub enum Collection {
    Users,
    AdminAssets,
    Accounts(Uuid),
    HostKeys(Uuid),
    Grants,
    Connections,
    Audit,
    Assets,
    Asset(Uuid),
}
impl PgStore {
    pub async fn list_page(
        &self,
        identity: &Identity,
        collection: Collection,
        page: PageRequest,
    ) -> StoreResult<Value> {
        let admin = identity.user.role == Role::Admin;
        let auditor = identity.user.role == Role::Auditor;
        match collection {
            Collection::Users
            | Collection::AdminAssets
            | Collection::Accounts(_)
            | Collection::HostKeys(_)
            | Collection::Grants
                if !admin =>
            {
                return Err(ErrorCode::PermissionDenied)
            }
            Collection::Audit if !admin && !auditor => return Err(ErrorCode::PermissionDenied),
            Collection::Assets | Collection::Asset(_) if auditor => {
                return Err(ErrorCode::PermissionDenied)
            }
            _ => {}
        }
        let scope = format!("{collection:?}:{}", identity.user.id);
        let cursor = page
            .cursor
            .map(|encoded| {
                if encoded.len() > 1024 {
                    return Err(ErrorCode::InvalidArgument);
                }
                let bytes = URL_SAFE_NO_PAD
                    .decode(encoded)
                    .map_err(|_| ErrorCode::InvalidArgument)?;
                let cursor: Cursor =
                    serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidArgument)?;
                if cursor.scope != scope {
                    return Err(ErrorCode::InvalidArgument);
                }
                Ok(cursor)
            })
            .transpose()?;
        let limit = page.limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(ErrorCode::InvalidArgument);
        }
        // The only interpolated SQL is this closed set of server-owned fragments.
        let (projection,table,time,filter,parent,descending)=match collection {
            Collection::Users=>("jsonb_build_object('id',u.id,'username',u.username,'role',u.role,'enabled',u.enabled,'revision',u.auth_revision)","users u","u.created_at","true",Uuid::nil(),false),
            Collection::AdminAssets=>("jsonb_build_object('id',u.id,'name',u.name,'host',u.host,'port',u.port,'tags',u.tags,'enabled',u.enabled,'revision',u.config_revision)","assets u","u.created_at","true",Uuid::nil(),false),
            Collection::Accounts(asset)=>("jsonb_build_object('id',u.id,'asset_id',u.asset_id,'username',u.username,'enabled',u.enabled,'revision',u.config_revision,'credential_kind',c.kind,'credential_revision',c.revision)","target_accounts u JOIN credentials c ON c.id=u.credential_id","u.created_at","u.asset_id=$4",asset,false),
            Collection::HostKeys(asset)=>("jsonb_build_object('id',u.id,'asset_id',u.asset_id,'algorithm',u.algorithm,'public_key',u.public_key,'fingerprint',u.fingerprint,'state',u.state,'revision',u.revision)","asset_host_keys u","u.created_at","u.asset_id=$4",asset,false),
            Collection::Grants=>("to_jsonb(u)","grants u","u.created_at","true",Uuid::nil(),false),
            Collection::Connections=>("jsonb_build_object('id',u.id,'ticket_id',u.ticket_id,'user_id',u.user_id,'login_session_id',u.login_session_id,'asset_id',u.asset_id,'account_id',u.account_id,'capabilities',u.capabilities,'purpose',u.purpose,'state',u.state,'created_at',u.created_at,'failure',CASE WHEN u.failure_code IS NULL THEN NULL ELSE jsonb_build_object('code',u.failure_code) END)","connections u","u.created_at","(u.user_id=$5 OR $6)",Uuid::nil(),false),
            Collection::Audit=>("to_jsonb(u)","audit_events u","u.occurred_at","true",Uuid::nil(),true),
            Collection::Assets|Collection::Asset(_)=>(ASSET_METADATA,"assets u","u.created_at",ASSET_FILTER,match collection {Collection::Asset(id)=>id,_=>Uuid::nil()},false),
        };
        let comparison = if descending { "<" } else { ">" };
        let direction = if descending { "DESC" } else { "ASC" };
        let query=format!("SELECT * FROM (SELECT {projection} AS data,{time} AS page_time,u.id AS page_id FROM {table} WHERE {filter} AND ($4::uuid IS NOT NULL) AND ($5::uuid IS NOT NULL) AND ($6::boolean IS NOT NULL)) q WHERE ($1::timestamptz IS NULL OR (page_time,page_id) {comparison} ($1,$2)) ORDER BY page_time {direction},page_id {direction} LIMIT $3");
        let mut rows = sqlx::query(&query)
            .bind(cursor.as_ref().map(|v| v.time))
            .bind(cursor.as_ref().map(|v| v.id))
            .bind(i64::from(limit) + 1)
            .bind(parent)
            .bind(identity.user.id)
            .bind(admin || auditor)
            .fetch_all(&self.pool)
            .await
            .map_err(super::postgres::db)?;
        let has_more = rows.len() > usize::from(limit);
        rows.truncate(usize::from(limit));
        let next = if has_more {
            let last = rows.last().unwrap();
            Some(
                URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&Cursor {
                        scope,
                        time: last.get("page_time"),
                        id: last.get("page_id"),
                    })
                    .map_err(|_| ErrorCode::InternalError)?,
                ),
            )
        } else {
            None
        };
        let values: Vec<Value> = rows.into_iter().map(|row| row.get("data")).collect();
        let mut result = json!({"items":values,"next_cursor":next});
        if matches!(collection, Collection::Assets | Collection::Asset(_)) {
            result["policy_revision"] = json!(self.policy_revision().await?);
        }
        Ok(result)
    }
}
const ASSET_FILTER:&str="u.enabled AND ($4='00000000-0000-0000-0000-000000000000'::uuid OR u.id=$4) AND EXISTS(SELECT 1 FROM target_accounts t JOIN grants g ON g.account_id=t.id AND g.asset_id=t.asset_id WHERE t.asset_id=u.id AND t.enabled AND g.user_id=$5 AND g.enabled AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()))";
const ASSET_METADATA:&str="jsonb_build_object('id',u.id,'name',u.name,'tags',u.tags,'revision',u.config_revision,'accounts',(SELECT jsonb_agg(a.data ORDER BY a.id) FROM (SELECT t.id,jsonb_build_object('id',t.id,'username',t.username,'capabilities',array_agg(DISTINCT cap ORDER BY cap)) AS data FROM target_accounts t JOIN grants g ON g.account_id=t.id AND g.asset_id=t.asset_id CROSS JOIN LATERAL unnest(g.capabilities) cap WHERE t.asset_id=u.id AND t.enabled AND g.user_id=$5 AND g.enabled AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()) GROUP BY t.id) a))";

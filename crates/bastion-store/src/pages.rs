use crate::{bounded, PgStore, StoreResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bastion_domain::{ConnectionState, ErrorCode, Identity, Role, TargetProtocol};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListFilter {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub actor_id: Option<Uuid>,
    pub resource_id: Option<Uuid>,
    pub resource_type: Option<String>,
    pub action: Option<String>,
    pub state: Option<ConnectionState>,
    pub target_protocol: Option<TargetProtocol>,
    pub connection_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub ungrouped: Option<bool>,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageRequest {
    pub limit: Option<u16>,
    pub cursor: Option<String>,
    #[serde(flatten)]
    pub filter: ListFilter,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    scope: String,
    time: DateTime<Utc>,
    id: Uuid,
}
#[derive(Clone, Copy, Debug)]
pub enum Collection {
    Users,
    AdminAssets,
    AssetGroups,
    Accounts(Uuid),
    Grants,
    Connections,
    Audit,
    Assets,
    Asset(Uuid),
    DeviceSessions,
    Recordings,
}
fn scope(identity: &Identity, collection: Collection, filter: &ListFilter) -> StoreResult<String> {
    Ok(format!(
        "{collection:?}:{}:{}:{}:{}",
        identity.user.id,
        identity.user.revision,
        identity.user.role.as_str(),
        serde_json::to_string(filter).map_err(|_| ErrorCode::InternalError)?
    ))
}
fn cursor(encoded: &str, scope: &str) -> StoreResult<Cursor> {
    if encoded.len() > 4096 {
        return Err(ErrorCode::InvalidArgument);
    }
    let value: Cursor = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ErrorCode::InvalidArgument)?,
    )
    .map_err(|_| ErrorCode::InvalidArgument)?;
    if value.scope != scope {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(value)
}
fn validate_filter(collection: Collection, f: &ListFilter) -> StoreResult<()> {
    if f.from.zip(f.to).is_some_and(|(a, b)| a > b)
        || [&f.action, &f.resource_type].iter().any(|v| {
            v.as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        })
    {
        return Err(ErrorCode::InvalidArgument);
    }
    let connections = matches!(collection, Collection::Connections);
    let audit = matches!(collection, Collection::Audit);
    let assets = matches!(
        collection,
        Collection::Assets | Collection::Asset(_) | Collection::AdminAssets
    );
    if (!matches!(collection, Collection::Recordings) && f.connection_id.is_some())
        || (!connections && (f.state.is_some() || f.target_protocol.is_some()))
        || (!audit && (f.action.is_some() || f.resource_type.is_some()))
        || (!connections && !audit && (f.actor_id.is_some() || f.resource_id.is_some()))
        || (!assets && (f.group_id.is_some() || f.ungrouped.is_some()))
        || (f.group_id.is_some() && f.ungrouped == Some(true))
    {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(())
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
            | Collection::AssetGroups
            | Collection::Accounts(_)
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
        validate_filter(collection, &page.filter)?;
        let limit = page.limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(ErrorCode::InvalidArgument);
        }
        let scope = scope(identity, collection, &page.filter)?;
        let cursor = page
            .cursor
            .as_deref()
            .map(|v| cursor(v, &scope))
            .transpose()?;
        // The only interpolated SQL is this closed set of server-owned fragments.
        let (projection,table,time,filter,parent,descending)=match collection {
            Collection::Users=>("jsonb_build_object('id',u.id,'username',u.username,'role',u.role,'enabled',u.enabled,'revision',u.auth_revision)","users u","u.created_at","u.deleted_at IS NULL",Uuid::nil(),false),
            Collection::AdminAssets=>("jsonb_build_object('id',u.id,'name',u.name,'host',u.host,'port',u.port,'tags',u.tags,'group_id',u.group_id,'enabled',u.enabled,'revision',u.config_revision,'routing_revision',u.routing_revision,'protocol',u.protocol,'security',u.security,'ssh_host_key',u.ssh_host_key,'rdp_certificate_sha256',u.rdp_certificate_sha256)","assets u","u.created_at",ADMIN_ASSET_FILTER,Uuid::nil(),false),
            Collection::AssetGroups=>("jsonb_build_object('id',u.id,'name',u.name,'revision',u.revision,'parent_id',u.parent_id,'sort_order',u.sort_order)","asset_groups u","u.created_at","true",Uuid::nil(),false),
            Collection::Accounts(asset)=>("jsonb_build_object('id',u.id,'asset_id',u.asset_id,'label',u.label,'username',u.username,'domain',u.domain,'enabled',u.enabled,'revision',u.config_revision,'credential_kind',COALESCE(c.kind,'none'),'credential_revision',c.revision)","target_accounts u LEFT JOIN credentials c ON c.id=u.credential_id","u.created_at",ACCOUNT_LIST_FILTER,asset,false),
            Collection::Grants=>("jsonb_build_object('id',u.id,'user_id',u.user_id,'asset_id',u.asset_id,'account_id',u.account_id,'enabled',u.enabled,'expires_at',u.expires_at,'revision',u.revision,'username',gu.username,'asset_name',ga.name,'account_label',gt.label)","grants u JOIN users gu ON gu.id=u.user_id JOIN assets ga ON ga.id=u.asset_id JOIN target_accounts gt ON gt.id=u.account_id","u.created_at","true",Uuid::nil(),false),
            Collection::Connections=>(CONNECTION_METADATA,"connections u","u.created_at","(u.user_id=$5 OR $6) AND ($9::uuid IS NULL OR u.user_id=$9) AND ($10::uuid IS NULL OR u.asset_id=$10) AND ($13::text IS NULL OR u.state=$13) AND ($14::text IS NULL OR u.target_protocol=$14)",Uuid::nil(),false),
            Collection::Audit=>(AUDIT_METADATA,"audit_events u","u.occurred_at","($9::uuid IS NULL OR u.actor_id=$9) AND ($10::uuid IS NULL OR u.resource_id=$10) AND ($11::text IS NULL OR u.resource_type=$11) AND ($12::text IS NULL OR u.action=$12)",Uuid::nil(),true),
            Collection::Assets|Collection::Asset(_)=>(ASSET_METADATA,"assets u","u.created_at",ASSET_FILTER,match collection {Collection::Asset(id)=>id,_=>Uuid::nil()},false),
            Collection::DeviceSessions=>("jsonb_build_object('id',u.id,'device_label',u.device_label,'current',u.id=$15,'created_at',u.created_at,'expires_at',u.expires_at,'revoked_at',u.revoked_at)","login_sessions u","u.created_at","u.user_id=$5",Uuid::nil(),false),
            Collection::Recordings=>("jsonb_build_object('id',u.id,'connection_id',u.connection_id,'target_protocol',u.target_protocol,'format_version',u.format_version,'bytes',u.bytes,'checksum',u.checksum,'state',u.state,'retention_until',u.retention_until,'last_written_seq',u.last_written_seq,'last_synced_seq',u.last_synced_seq)","recordings u JOIN connections c ON c.id=u.connection_id","u.created_at","(c.user_id=$5 OR $6) AND ($16::uuid IS NULL OR u.connection_id=$16)",Uuid::nil(),false),
        };
        let comparison = if descending { "<" } else { ">" };
        let direction = if descending { "DESC" } else { "ASC" };
        let query=format!("SELECT * FROM (SELECT {projection} AS data,{time} AS page_time,u.id AS page_id FROM {table} WHERE {filter} AND ($4::uuid IS NOT NULL) AND ($5::uuid IS NOT NULL) AND ($6::boolean IS NOT NULL) AND ($7::timestamptz IS NULL OR {time}>=$7) AND ($8::timestamptz IS NULL OR {time}<=$8) AND ($9::uuid IS NULL OR $9 IS NOT NULL) AND ($10::uuid IS NULL OR $10 IS NOT NULL) AND ($11::text IS NULL OR $11 IS NOT NULL) AND ($12::text IS NULL OR $12 IS NOT NULL) AND ($13::text IS NULL OR $13 IS NOT NULL) AND ($14::text IS NULL OR $14 IS NOT NULL) AND ($15::uuid IS NOT NULL) AND ($16::uuid IS NULL OR $16 IS NOT NULL) AND ($17::uuid IS NULL OR $17 IS NOT NULL) AND ($18::boolean IS NOT NULL)) q WHERE ($1::timestamptz IS NULL OR (page_time,page_id) {comparison} ($1,$2::uuid)) ORDER BY page_time {direction},page_id {direction} LIMIT $3");
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, identity, false).await?;
            if matches!(collection, Collection::Connections) {
                super::postgres::expire_tickets(&mut tx).await?;
            }
            let mut rows = sqlx::query(&query)
                .bind(cursor.as_ref().map(|v| v.time))
                .bind(cursor.as_ref().map(|v| v.id))
                .bind(i64::from(limit) + 1)
                .bind(parent)
                .bind(identity.user.id)
                .bind(admin || auditor)
                .bind(page.filter.from)
                .bind(page.filter.to)
                .bind(page.filter.actor_id)
                .bind(page.filter.resource_id)
                .bind(&page.filter.resource_type)
                .bind(&page.filter.action)
                .bind(page.filter.state.map(|s| {
                    serde_json::to_value(s)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_owned()
                }))
                .bind(page.filter.target_protocol.map(TargetProtocol::as_str))
                .bind(identity.login_session_id)
                .bind(page.filter.connection_id)
                .bind(page.filter.group_id)
                .bind(page.filter.ungrouped.unwrap_or(false))
                .fetch_all(&mut *tx)
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
                result["policy_revision"] = json!(sqlx::query_scalar::<_, i64>(
                    "SELECT policy_revision FROM server_settings WHERE singleton"
                )
                .fetch_one(&mut *tx)
                .await
                .map_err(super::postgres::db)?);
            }
            // The client tree needs the group hierarchy alongside the assets it may reach; ancestor groups come along.
            if matches!(collection, Collection::Assets) {
                result["groups"] =
                    sqlx::query_scalar::<_, Value>(super::groups::visible_groups_sql())
                        .bind(parent)
                        .bind(identity.user.id)
                        .bind(admin || auditor)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(super::postgres::db)?;
            }
            tx.commit().await.map_err(super::postgres::db)?;
            Ok(result)
        })
        .await
    }
}
const CONNECTION_METADATA:&str="jsonb_build_object('id',u.id,'ticket_id',u.ticket_id,'user_id',u.user_id,'login_session_id',u.login_session_id,'asset_id',u.asset_id,'account_id',u.account_id,'target_protocol',u.target_protocol,'protocol_version',u.protocol_version,'display',jsonb_build_object('width',u.width,'height',u.height,'dpi',u.dpi),'state',u.state,'created_at',u.created_at,'started_at',u.started_at,'ended_at',u.ended_at,'user_snapshot',u.user_snapshot,'asset_snapshot',u.asset_snapshot,'bytes_in',u.bytes_in,'bytes_out',u.bytes_out,'failure',CASE WHEN u.failure_code IS NULL THEN NULL ELSE jsonb_build_object('code',canonical_failure_code(u.failure_code)) END,'recording_id',(SELECT r.id FROM recordings r WHERE r.connection_id=u.id))";
const AUDIT_METADATA:&str="to_jsonb(u) || jsonb_build_object('sanitized_payload',CASE WHEN jsonb_typeof(u.sanitized_payload->'reason_code')='string' THEN jsonb_set(u.sanitized_payload,'{reason_code}',to_jsonb(canonical_failure_code(u.sanitized_payload->>'reason_code'))) ELSE u.sanitized_payload END)";
const ASSET_FILTER:&str="u.enabled AND u.deleted_at IS NULL AND ($4='00000000-0000-0000-0000-000000000000'::uuid OR u.id=$4) AND ($6 OR EXISTS(SELECT 1 FROM target_accounts t JOIN grants g ON g.account_id=t.id AND g.asset_id=t.asset_id WHERE t.asset_id=u.id AND t.enabled AND t.deleted_at IS NULL AND g.user_id=$5 AND g.enabled AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()))) AND ($17::uuid IS NULL OR u.group_id=$17) AND (NOT $18 OR u.group_id IS NULL)";
// Assets/Asset reject auditors above, so $6 (admin || auditor) is admin-only here.
const ADMIN_ASSET_FILTER:&str="u.deleted_at IS NULL AND ($17::uuid IS NULL OR u.group_id=$17) AND (NOT $18 OR u.group_id IS NULL)";
const ACCOUNT_LIST_FILTER:&str="u.asset_id=$4 AND u.deleted_at IS NULL";
const ASSET_METADATA:&str="jsonb_build_object('id',u.id,'name',u.name,'protocol',u.protocol,'tags',u.tags,'group_id',u.group_id,'group_name',(SELECT name FROM asset_groups WHERE id=u.group_id),'revision',u.config_revision,'accounts',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',t.id,'label',t.label,'username',t.username,'domain',t.domain,'credential_kind',COALESCE(c.kind,'none')) ORDER BY t.id) FROM target_accounts t LEFT JOIN credentials c ON c.id=t.credential_id WHERE t.asset_id=u.id AND t.enabled AND t.deleted_at IS NULL AND ($6 OR EXISTS(SELECT 1 FROM grants g WHERE g.account_id=t.id AND g.asset_id=t.asset_id AND g.user_id=$5 AND g.enabled AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp())))),'[]'::jsonb))";
#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> Identity {
        Identity {
            user: bastion_domain::UserView {
                id: Uuid::new_v4(),
                username: "user".into(),
                role: Role::Admin,
                enabled: true,
                revision: 1,
            },
            login_session_id: Uuid::new_v4(),
        }
    }
    #[test]
    fn cursor_binds_identity_collection_filters_and_role() {
        let mut who = identity();
        let filter = ListFilter::default();
        let original = scope(&who, Collection::Connections, &filter).unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&Cursor {
                scope: original.clone(),
                time: Utc::now(),
                id: Uuid::new_v4(),
            })
            .unwrap(),
        );
        assert!(cursor(&encoded, &original).is_ok());
        let mut changed = filter.clone();
        changed.target_protocol = Some(TargetProtocol::Rdp);
        assert!(cursor(
            &encoded,
            &scope(&who, Collection::Connections, &changed).unwrap()
        )
        .is_err());
        who.user.role = Role::Operator;
        assert!(cursor(
            &encoded,
            &scope(&who, Collection::Connections, &filter).unwrap()
        )
        .is_err());
        assert!(cursor(&encoded, &scope(&who, Collection::Audit, &filter).unwrap()).is_err());
        assert!(cursor(&"x".repeat(4097), &original).is_err());
    }
    #[test]
    fn page_filters_are_typed_and_unknown_fields_rejected() {
        let page: PageRequest =
            serde_json::from_value(json!({"limit":20,"state":"active","target_protocol":"rdp"}))
                .unwrap();
        assert_eq!(page.filter.state, Some(ConnectionState::Active));
        assert!(serde_json::from_value::<PageRequest>(json!({"state":"reopened"})).is_err());
        assert!(serde_json::from_value::<PageRequest>(json!({"surprise":1})).is_err());
        assert!(validate_filter(Collection::Audit, &page.filter).is_err());
    }
    #[test]
    fn public_projections_do_not_expose_credentials_or_recording_keys() {
        assert!(CONNECTION_METADATA.contains("'target_protocol'"));
        assert!(CONNECTION_METADATA.contains("'protocol_version'"));
        assert!(CONNECTION_METADATA.contains("canonical_failure_code"));
        assert!(!CONNECTION_METADATA.contains("secret_hash"));
        assert!(!CONNECTION_METADATA.contains("wrapped_dek"));
    }
    /// The ZeroTerm client tree needs the hierarchy next to the assets; it must never widen what a user can see.
    #[test]
    fn visible_groups_carry_the_hierarchy_and_stay_inside_the_access_filter() {
        let sql = super::super::groups::visible_groups_sql();
        for field in ["'id'", "'name'", "'parent_id'", "'sort_order'"] {
            assert!(sql.contains(field), "missing {field}");
        }
        assert!(
            sql.contains("WITH RECURSIVE"),
            "ancestors are not collected"
        );
        assert!(sql.contains("target_accounts"), "grants are not applied");
        assert!(
            sql.contains("g.user_id=$2::uuid"),
            "group visibility ignores the requester"
        );
        assert!(
            sql.contains("a.enabled"),
            "disabled assets must not expose their group"
        );
        assert!(
            !sql.contains("revision"),
            "the client contract has no revision field"
        );
        // Ancestors come along even when they hold no accessible asset of their own.
        assert!(sql.contains("SELECT g.parent_id FROM asset_groups g JOIN reachable"));
        // Standalone statement with three binds: placeholders must start at $1 and stay contiguous,
        // otherwise PostgreSQL rejects the whole /assets request with a parameter-count error.
        let used: Vec<&str> = ["$1", "$2", "$3", "$4", "$5", "$6"]
            .into_iter()
            .filter(|p| sql.contains(*p))
            .collect();
        assert_eq!(used, vec!["$1", "$2", "$3"], "unexpected bind numbering");
        assert!(
            !sql.contains("$4"),
            "a $4 placeholder would demand a fourth bind"
        );
    }

    /// Soft deletion must hide the resource everywhere it can be listed or mutated, while the row survives.
    #[test]
    fn every_asset_and_account_read_hides_soft_deleted_rows() {
        // The admin catalogs have their own filter strings, so each needs its own guard.
        assert!(
            ADMIN_ASSET_FILTER.contains("u.deleted_at IS NULL"),
            "deleted assets would still be listed to administrators"
        );
        assert!(
            ACCOUNT_LIST_FILTER.contains("u.deleted_at IS NULL"),
            "deleted accounts would still be listed in the asset editor"
        );
        assert!(
            ASSET_FILTER.contains("u.deleted_at IS NULL"),
            "deleted assets would still reach clients"
        );
        assert!(
            ASSET_FILTER.contains("t.deleted_at IS NULL"),
            "a deleted account would still be reachable through a grant"
        );
        assert!(
            ASSET_METADATA.contains("t.deleted_at IS NULL"),
            "a deleted account would still be embedded in the asset payload"
        );
        assert!(
            super::super::groups::visible_groups_sql().contains("a.deleted_at IS NULL"),
            "a deleted asset would still expose its group"
        );
    }
}

use crate::{postgres::*, *};
use bastion_domain::{ErrorCode, Identity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use uuid::Uuid;

/// Groups a client may see: the ones holding an asset it can reach, plus their ancestors so a tree never orphans.
/// This runs as its own statement with exactly three binds, so the placeholders are $1=collection id,
/// $2=requester, $3=admin-or-auditor. It deliberately restates the ASSET_FILTER predicate instead of
/// borrowing its $4/$5/$6 numbering, which would make PostgreSQL demand six binds here.
const VISIBLE_GROUPS: &str = r#"WITH RECURSIVE seeded AS (
        SELECT DISTINCT a.group_id AS id
        FROM assets a
        WHERE a.group_id IS NOT NULL AND a.enabled AND a.deleted_at IS NULL
          AND ($1::uuid='00000000-0000-0000-0000-000000000000' OR a.id=$1::uuid)
          AND ($3::boolean OR EXISTS(SELECT 1 FROM target_accounts t JOIN grants g ON g.account_id=t.id AND g.asset_id=t.asset_id
                             WHERE t.asset_id=a.id AND t.enabled AND t.deleted_at IS NULL AND g.user_id=$2::uuid AND g.enabled
                               AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp())))
    ), reachable(id) AS (
        SELECT id FROM seeded
        UNION
        SELECT g.parent_id FROM asset_groups g JOIN reachable r ON g.id=r.id WHERE g.parent_id IS NOT NULL
    )
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id',g.id,'name',g.name,'parent_id',g.parent_id,'sort_order',g.sort_order
    ) ORDER BY g.sort_order,g.name,g.id),'[]'::jsonb)
    FROM asset_groups g JOIN reachable r ON r.id=g.id"#;

pub(super) fn visible_groups_sql() -> &'static str {
    VISIBLE_GROUPS
}

fn valid_name(raw: &str) -> StoreResult<&str> {
    let name = raw.trim();
    if name.is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) {
        Err(ErrorCode::InvalidArgument)
    } else {
        Ok(name)
    }
}

/// Create body: `parent_id` and `sort_order` establish where the new group sits in the tree.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetGroupCreateInput {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    #[serde(default)]
    pub sort_order: Option<i32>,
}
impl AssetGroupCreateInput {
    fn name(&self) -> StoreResult<&str> {
        valid_name(&self.name)
    }
    fn sort_order(&self) -> i32 {
        self.sort_order.unwrap_or(0)
    }
}
/// Patch body: every field is optional, but at least one must be present. `parent_id: null` moves a group to the root.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AssetGroupPatchInput {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    pub parent_id: Option<Option<Uuid>>,
    pub sort_order: Option<i32>,
}
impl AssetGroupPatchInput {
    fn name(&self) -> StoreResult<Option<&str>> {
        self.name.as_deref().map(valid_name).transpose()
    }
    fn sort_order(&self) -> StoreResult<i32> {
        match self.sort_order {
            None => Ok(0),
            Some(value) if (-100_000..=100_000).contains(&value) => Ok(value),
            Some(_) => Err(ErrorCode::InvalidArgument),
        }
    }
    fn touches(&self) -> bool {
        self.name.is_some() || self.parent_id.is_some() || self.sort_order.is_some()
    }
}

#[derive(Serialize, Clone)]
pub struct AssetGroupView {
    pub id: Uuid,
    pub name: String,
    pub revision: i64,
    pub parent_id: Option<Uuid>,
    pub sort_order: i32,
}
fn view(row: &PgRow) -> AssetGroupView {
    AssetGroupView {
        id: row.get("id"),
        name: row.get("name"),
        revision: row.get("revision"),
        parent_id: row.get("parent_id"),
        sort_order: row.get("sort_order"),
    }
}

pub(super) async fn require_group(
    tx: &mut Transaction<'_, Postgres>,
    group: Option<Uuid>,
) -> StoreResult<()> {
    if let Some(id) = group {
        sqlx::query("SELECT id FROM asset_groups WHERE id=$1 FOR KEY SHARE")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .ok_or(ErrorCode::ResourceNotFound)?;
    }
    Ok(())
}
/// A tree must stay acyclic, so reject a parent that is the group itself or one of its descendants.
async fn require_acyclic(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    parent: Option<Uuid>,
) -> StoreResult<()> {
    let mut cursor = parent;
    let mut steps = 0;
    while let Some(current) = cursor {
        if current == id || steps > 64 {
            return Err(ErrorCode::InvalidArgument);
        }
        cursor =
            sqlx::query_scalar::<_, Option<Uuid>>("SELECT parent_id FROM asset_groups WHERE id=$1")
                .bind(current)
                .fetch_optional(&mut **tx)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
        steps += 1;
    }
    Ok(())
}
impl PgStore {
    pub async fn asset_group(&self, id: Uuid) -> StoreResult<AssetGroupView> {
        let row = sqlx::query("SELECT * FROM asset_groups WHERE id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or(ErrorCode::ResourceNotFound)?;
        Ok(view(&row))
    }
    pub async fn create_asset_group(
        &self,
        actor: &Identity,
        input: &AssetGroupCreateInput,
        request_id: Uuid,
    ) -> StoreResult<AssetGroupView> {
        let name = input.name()?;
        let parent = input.parent_id;
        let sort_order = input.sort_order();
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, actor, true).await?;
            require_group(&mut tx, parent).await?;
            let id = Uuid::new_v4();
            require_acyclic(&mut tx, id, parent).await?;
            let row = sqlx::query("INSERT INTO asset_groups(id,name,parent_id,sort_order) VALUES($1,$2,$3,$4) RETURNING *")
                .bind(id)
                .bind(name)
                .bind(parent)
                .bind(sort_order)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
            let group = view(&row);
            audit(
                &mut tx,
                Some(actor.user.id),
                Some(actor.login_session_id),
                "asset_group.created",
                "asset_group",
                Some(group.id),
                request_id,
                json!({"name":group.name,"parent_id":group.parent_id,"sort_order":group.sort_order}),
            )
            .await?;
            tx.commit().await.map_err(db)?;
            Ok(group)
        })
        .await
    }
    /// Renames and/or moves a group. `parent_id: null` moves it to the root; an absent field leaves it alone.
    pub async fn patch_asset_group(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        input: &AssetGroupPatchInput,
        request_id: Uuid,
    ) -> StoreResult<AssetGroupView> {
        if !input.touches() {
            return Err(ErrorCode::InvalidArgument);
        }
        let name = input.name()?;
        let parent = input.parent_id;
        let sort_order = input.sort_order()?;
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, actor, true).await?;
            let before = sqlx::query("SELECT * FROM asset_groups WHERE id=$1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
            if before.get::<i64, _>("revision") != revision {
                return Err(ErrorCode::RevisionConflict);
            }
            let next_name = match name {
                Some(value) => value.to_owned(),
                None => before.get::<String, _>("name"),
            };
            let next_parent = match &parent {
                Some(value) => *value,
                None => before.get::<Option<Uuid>, _>("parent_id"),
            };
            let next_sort = if input.sort_order.is_some() {
                sort_order
            } else {
                before.get::<i32, _>("sort_order")
            };
            require_group(&mut tx, next_parent).await?;
            require_acyclic(&mut tx, id, next_parent).await?;
            // A group carrying assets cannot be re-parented into its own subtree: its assets would follow it.
            let carried: i64 = sqlx::query_scalar("SELECT count(*) FROM assets WHERE group_id=$1")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
            let row = sqlx::query("UPDATE asset_groups SET name=$2,parent_id=$3,sort_order=$4,revision=revision+1 WHERE id=$1 RETURNING *")
                .bind(id)
                .bind(next_name)
                .bind(next_parent)
                .bind(next_sort)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
            let group = view(&row);
            audit(
                &mut tx,
                Some(actor.user.id),
                Some(actor.login_session_id),
                if name.is_some() { "asset_group.renamed" } else { "asset_group.moved" },
                "asset_group",
                Some(id),
                request_id,
                json!({"name":group.name,"parent_id":group.parent_id,"sort_order":group.sort_order,"assets":carried}),
            )
            .await?;
            tx.commit().await.map_err(db)?;
            Ok(group)
        })
        .await
    }
    /// Deleting a group moves its assets to the root and its child groups up to its own parent; the tree never dangles.
    pub async fn delete_asset_group(
        &self,
        actor: &Identity,
        id: Uuid,
        revision: i64,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, actor, true).await?;
            let before = sqlx::query("SELECT * FROM asset_groups WHERE id=$1 FOR UPDATE")
                .bind(id).fetch_optional(&mut *tx).await.map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
            if before.get::<i64,_>("revision") != revision { return Err(ErrorCode::RevisionConflict); }
            let parent = before.get::<Option<Uuid>,_>("parent_id");
            let moved = sqlx::query("UPDATE assets SET group_id=NULL,config_revision=config_revision+1 WHERE group_id=$1")
                .bind(id).execute(&mut *tx).await.map_err(db)?.rows_affected();
            let reparented = sqlx::query("UPDATE asset_groups SET parent_id=$2,revision=revision+1 WHERE parent_id=$1")
                .bind(id).bind(parent).execute(&mut *tx).await.map_err(db)?.rows_affected();
            sqlx::query("DELETE FROM asset_groups WHERE id=$1").bind(id).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx, Some(actor.user.id), Some(actor.login_session_id), "asset_group.deleted", "asset_group", Some(id), request_id,
                json!({"name":before.get::<String,_>("name"),"assets_ungrouped":moved,"child_groups_reparented":reparented})).await?;
            tx.commit().await.map_err(db)?;
            Ok(())
        }).await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn group_name_validation() {
        for name in ["", " \t ", "bad\0name", "bad\nname"] {
            assert!(valid_name(name).is_err());
        }
        assert!(valid_name(&"组".repeat(129)).is_err());
        assert_eq!(valid_name(" 测试 ").unwrap(), "测试");
        assert!(valid_name(&"组".repeat(128)).is_ok());
    }
    #[test]
    fn patch_null_parent_means_move_to_root() {
        let root: AssetGroupPatchInput = serde_json::from_str(r#"{"parent_id":null}"#).unwrap();
        assert_eq!(root.parent_id, Some(None));
        let absent: AssetGroupPatchInput = serde_json::from_str(r#"{"name":"a"}"#).unwrap();
        assert_eq!(absent.parent_id, None);
    }
    #[test]
    fn patch_requires_at_least_one_field_and_bounds_sort_order() {
        assert!(!AssetGroupPatchInput::default().touches());
        assert!(AssetGroupPatchInput {
            name: Some("a".into()),
            ..Default::default()
        }
        .touches());
        assert!(AssetGroupPatchInput {
            parent_id: Some(None),
            ..Default::default()
        }
        .touches());
        assert!(AssetGroupPatchInput {
            sort_order: Some(0),
            ..Default::default()
        }
        .touches());
        for order in [-100_000, 100_000] {
            assert_eq!(
                AssetGroupPatchInput {
                    sort_order: Some(order),
                    ..Default::default()
                }
                .sort_order()
                .unwrap(),
                order
            );
        }
        for order in [i32::MIN, i32::MAX, 100_001] {
            assert!(AssetGroupPatchInput {
                sort_order: Some(order),
                ..Default::default()
            }
            .sort_order()
            .is_err());
        }
    }
}

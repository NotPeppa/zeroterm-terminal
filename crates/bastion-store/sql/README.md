# Audit partition maintenance (offline)

`audit_partition_upgrade.sql` is **not** an automatic SQLx migration. Run it only
through `bastion_store::audit_partition_upgrade` with the gateway stopped and no
other application sessions connected to the database. It requires the current
user to own `public.audit_events` and have `CREATE` on the schema. The operation
copies rows into a range-partitioned parent, preserves the append-only trigger,
verifies counts, and keeps a default partition for out-of-window writes.

`maintain_audit_partitions` creates the current and next UTC month and can drop
at most one catalog-verified monthly partition per call when its upper bound is
older than the requested retention period. It never drops the default partition
and refuses overlap, registry drift, owner/schema drift, missing inheritance,
or a missing append-only trigger. Repeat the call offline until `dropped` is
`None`; a nonzero `default_rows` means retention is incomplete and needs an
explicit offline rebuild.

Use separate database roles operationally: the runtime role needs only the
application's normal table permissions and must not own the audit parent or
have schema `CREATE`; the maintenance role owns the audit parent/registry and
is used only for the stopped-gateway procedure. Role creation and grants are a
manual deployment responsibility; this crate does not create roles or use
`SECURITY DEFINER`, `set role`, `session_replication_role`, or ordinary DELETE.
Every DDL transaction is bounded to two seconds; large upgrades intentionally
fail and roll back rather than extending the production transaction budget.

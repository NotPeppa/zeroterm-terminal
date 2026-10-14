#!/bin/sh
# Run as the default root user in the postgres container, never as the PostgreSQL UID.
set -eu

runtime_password=$(cat /run/bastion-runtime/password)
test "${#runtime_password}" -eq 64
case "$runtime_password" in
    *[!0123456789abcdef]*) exit 1 ;;
esac

database_name=${POSTGRES_DB:-bastion}
case "$database_name" in ''|*[!a-zA-Z0-9_]*) exit 1 ;; esac
psql_args="--username=bastion --dbname=$database_name --no-psqlrc --set=ON_ERROR_STOP=1 --set=database_name=$database_name"
psql $psql_args <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bastion_runtime') THEN
        CREATE ROLE bastion_runtime LOGIN;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'bastion_runtime'))
       OR EXISTS (SELECT 1 FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles WHERE rolname = 'bastion_runtime'))
       OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner = (SELECT oid FROM pg_roles WHERE rolname = 'bastion_runtime'))
       OR EXISTS (SELECT 1 FROM pg_database WHERE datdba = (SELECT oid FROM pg_roles WHERE rolname = 'bastion_runtime')) THEN
        RAISE EXCEPTION 'bastion_runtime must not own objects or have role memberships';
    END IF;
END
$$;
ALTER ROLE bastion_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
SQL

# psql hashes the password client-side; plaintext never reaches SQL, argv, env or Docker logs.
printf '%s\n%s\n' "$runtime_password" "$runtime_password" \
    | psql $psql_args --command='\password bastion_runtime'
unset runtime_password

psql $psql_args <<'SQL'
BEGIN;
REVOKE ALL PRIVILEGES ON DATABASE :"database_name" FROM bastion_runtime;
GRANT CONNECT ON DATABASE :"database_name" TO bastion_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM bastion_runtime;
GRANT USAGE ON SCHEMA public TO bastion_runtime;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM bastion_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bastion_runtime;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM bastion_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO bastion_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bastion IN SCHEMA public
    REVOKE ALL ON TABLES FROM bastion_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE bastion IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM bastion_runtime;
REVOKE ALL ON TABLE public._sqlx_migrations FROM bastion_runtime;
GRANT SELECT ON TABLE public._sqlx_migrations TO bastion_runtime;
DO $$
DECLARE audit_table record;
BEGIN
    -- Follow the real inheritance tree, including nested or renamed partitions.
    FOR audit_table IN
        WITH RECURSIVE audit_relations(oid) AS (
            SELECT 'public.audit_events'::regclass::oid
            UNION
            SELECT i.inhrelid FROM pg_inherits i JOIN audit_relations a ON i.inhparent = a.oid
        )
        SELECT n.nspname, c.relname FROM audit_relations a
            JOIN pg_class c ON c.oid = a.oid JOIN pg_namespace n ON n.oid = c.relnamespace
    LOOP
        EXECUTE format('REVOKE ALL ON TABLE %I.%I FROM bastion_runtime', audit_table.nspname, audit_table.relname);
        EXECUTE format('GRANT SELECT, INSERT ON TABLE %I.%I TO bastion_runtime', audit_table.nspname, audit_table.relname);
    END LOOP;
    IF to_regclass('public.audit_partition_registry') IS NOT NULL THEN
        REVOKE ALL ON TABLE public.audit_partition_registry FROM bastion_runtime;
        GRANT SELECT ON TABLE public.audit_partition_registry TO bastion_runtime;
    END IF;
END
$$;
COMMIT;
SQL
printf '%s\n' 'Docker runtime role and grants refreshed.'

-- OFFLINE OWNER-ONLY upgrade, deliberately outside automatic SQLx migrations.
-- Run only through audit_partition_upgrade(), with the gateway stopped and no
-- other database sessions. A 2-second timeout rolls the whole upgrade back.
-- Existing append-only trigger is never disabled; copying uses INSERT only.
DO $$
DECLARE
    old_table oid := 'public.audit_events'::regclass;
    month_start timestamptz;
    month_end timestamptz;
    partition_name text;
    old_count bigint;
    new_count bigint;
BEGIN
    IF EXISTS(SELECT 1 FROM pg_constraint WHERE confrelid=old_table) THEN
        RAISE EXCEPTION 'audit upgrade refuses incoming foreign keys' USING ERRCODE='23505';
    END IF;
    IF EXISTS(SELECT 1 FROM pg_partitioned_table WHERE partrelid=old_table) THEN
        RAISE EXCEPTION 'audit table already partitioned' USING ERRCODE='23505';
    END IF;
    ALTER TABLE public.audit_events RENAME TO audit_events_prepartition;
    CREATE TABLE public.audit_events (
        id uuid NOT NULL,
        occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
        actor_id uuid REFERENCES public.users(id),
        login_session_id uuid REFERENCES public.login_sessions(id),
        action text NOT NULL,
        resource_type text NOT NULL,
        resource_id uuid,
        request_id uuid NOT NULL,
        sanitized_payload jsonb NOT NULL DEFAULT '{}',
        CONSTRAINT audit_events_partitioned_pk PRIMARY KEY(id,occurred_at)
    ) PARTITION BY RANGE(occurred_at);
    CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON public.audit_events
        FOR EACH ROW EXECUTE FUNCTION public.audit_append_only();
    CREATE INDEX audit_events_partitioned_time ON public.audit_events(occurred_at,id);
    CREATE INDEX audit_events_partitioned_actor ON public.audit_events(actor_id,occurred_at,id);
    CREATE INDEX audit_events_partitioned_resource ON public.audit_events(resource_type,resource_id,occurred_at,id);
    CREATE TABLE public.audit_partition_registry (
        partition_name text PRIMARY KEY,
        relation_oid oid NOT NULL UNIQUE,
        lower_bound timestamptz NOT NULL,
        upper_bound timestamptz NOT NULL,
        bound_expression text NOT NULL,
        CHECK (upper_bound>lower_bound)
    );
    REVOKE ALL ON public.audit_partition_registry FROM PUBLIC;
    REVOKE ALL ON public.audit_events FROM PUBLIC;
    -- Only months containing history plus current/next are created, not an
    -- unbounded generate_series over sparse, user-selected ancient timestamps.
    FOR month_start IN
        SELECT DISTINCT date_trunc('month',occurred_at) FROM public.audit_events_prepartition
        UNION SELECT date_trunc('month',clock_timestamp())
        UNION SELECT date_trunc('month',clock_timestamp())+interval '1 month'
        ORDER BY 1
    LOOP
        month_end := month_start+interval '1 month';
        IF extract(year FROM month_start) NOT BETWEEN 1 AND 9999 THEN
            RAISE EXCEPTION 'audit timestamp outside supported partition years' USING ERRCODE='23514';
        END IF;
        partition_name := 'audit_events_m_'||to_char(month_start,'YYYYMM');
        EXECUTE format('CREATE TABLE public.%I PARTITION OF public.audit_events FOR VALUES FROM (%L) TO (%L)',partition_name,month_start,month_end);
        INSERT INTO public.audit_partition_registry
            SELECT partition_name,c.oid,month_start,month_end,pg_get_expr(c.relpartbound,c.oid)
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname=partition_name;
    END LOOP;
    CREATE TABLE public.audit_events_default PARTITION OF public.audit_events DEFAULT;
    INSERT INTO public.audit_events SELECT * FROM public.audit_events_prepartition;
    SELECT count(*) INTO old_count FROM public.audit_events_prepartition;
    SELECT count(*) INTO new_count FROM public.audit_events;
    IF old_count<>new_count THEN
        RAISE EXCEPTION 'audit copy verification failed' USING ERRCODE='23514';
    END IF;
    DROP TABLE public.audit_events_prepartition;
END $$;

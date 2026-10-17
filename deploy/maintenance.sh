#!/bin/sh
# Optional, manual disk maintenance for the Docker Compose deployment. Nothing here runs on a schedule.
# Run from the directory holding compose.yaml and .env:
#
#   sh deploy/maintenance.sh status                     read-only: disk usage and what clean would remove
#   sh deploy/maintenance.sh partition-audit            one-time: allow audit retention (brief downtime)
#   sh deploy/maintenance.sh clean [--audit-days N]     delete expired recordings and audit months (brief downtime)
#
# Add --yes to skip the confirmation prompt.
# partition-audit and clean stop the bastion service, which disconnects every live session, and start it again
# afterwards. Deletion cannot be undone; take a backup first if you may need the data.
set -eu

usage() {
    # Prints the header comment above.
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
    exit "${1:-0}"
}

dc() { docker compose "$@"; }
sql() { dc exec -T postgres psql -U bastion -d bastion -v ON_ERROR_STOP=1 -qtA -F ' | ' -c "$1"; }
tool() { dc run --rm --no-deps maintenance "$@" --config /etc/zeroterm-bastion/maintenance.toml; }
partitioned() {
    test "$(sql "SELECT EXISTS(SELECT 1 FROM pg_partitioned_table WHERE partrelid='public.audit_events'::regclass)")" = t
}

# Recordings the clean command may remove: past retention and not attached to a live connection.
expired_recordings="FROM recordings r JOIN connections c ON c.id=r.connection_id
    WHERE r.state IN ('complete','partial','failed','corrupt','missing')
    AND c.state IN ('closed','failed','expired','revoked','interrupted') AND r.retention_until<=clock_timestamp()"
audit_relations="SELECT 'public.audit_events'::regclass AS oid UNION SELECT inhrelid FROM pg_inherits
    WHERE inhparent='public.audit_events'::regclass"

confirm() {
    test "$assume_yes" = 1 && return 0
    printf '%s [y/N] ' "$1"
    read -r answer || answer=
    case "$answer" in y|Y|yes|YES) ;; *) echo 'Cancelled; nothing was changed.'; exit 1 ;; esac
}

# Stops bastion for an offline step and brings back exactly the services that were running before,
# so a deployment behind its own reverse proxy does not suddenly start the bundled one.
running=
stop_app() {
    running=$(dc ps --status running --services | tr '\n' ' ')
    case " $running " in *' bastion '*) ;; *) running="$running bastion" ;; esac
    echo 'Stopping bastion; live sessions are disconnected.'
    dc stop bastion
    trap restart_app EXIT
}
restart_app() {
    trap - EXIT
    echo "Starting:$running"
    # shellcheck disable=SC2086 # service names are intentionally split
    dc up -d --wait $running
}

status() {
    echo '== Recording volume'
    dc run --rm --no-deps --entrypoint sh maintenance -c \
        'df -h /var/lib/zeroterm-bastion/recordings | tail -n 1; du -sh /var/lib/zeroterm-bastion/recordings'
    echo
    echo '== Recordings (count | size)'
    sql "SELECT 'stored', count(*), pg_size_pretty(COALESCE(sum(bytes),0)) FROM recordings WHERE state<>'expired'"
    sql "SELECT 'expired, removable by clean', count(*), pg_size_pretty(COALESCE(sum(r.bytes),0)) $expired_recordings"
    echo
    echo '== Database'
    sql "SELECT 'database total', pg_size_pretty(pg_database_size(current_database()))"
    sql "SELECT 'audit events', count(*), 'oldest '||COALESCE(min(occurred_at)::date::text,'-') FROM audit_events"
    sql "SELECT 'audit storage', pg_size_pretty(sum(pg_total_relation_size(oid))) FROM ($audit_relations) a"
    if partitioned; then
        sql "SELECT 'audit months', count(*), COALESCE(min(lower_bound)::date::text,'-')||' .. '||COALESCE(max(upper_bound)::date::text,'-') FROM audit_partition_registry"
        sql "SELECT 'rows outside managed months (never removed)', count(*) FROM audit_events_default"
    else
        echo 'audit retention: not enabled yet; run "partition-audit" once (best while the log is small)'
    fi
}

partition_audit() {
    if partitioned; then echo 'Audit events are already partitioned; nothing to do.'; return; fi
    confirm 'Convert the audit log to monthly partitions? bastion stops briefly.'
    stop_app
    tool partition-audit --offline
    # Conversion creates only the current and next month. A retention pass with the maximum period drops
    # nothing but creates the following twelve months, so rare maintenance never pushes new events into the
    # never-dropped default partition.
    tool retain-audit --offline --days 3650
    restart_app
}

clean() {
    days=180
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --audit-days) [ "$#" -ge 2 ] || usage 2; days=$2; shift 2 ;;
            *) usage 2 ;;
        esac
    done
    case "$days" in ''|*[!0-9]*) echo 'audit days must be a number between 1 and 3650' >&2; exit 2 ;; esac
    if [ "$days" -lt 1 ] || [ "$days" -gt 3650 ]; then echo 'audit days must be between 1 and 3650' >&2; exit 2; fi
    audit=1
    partitioned || { audit=0; echo 'Audit retention is not enabled (run "partition-audit" once); only recordings are cleaned.'; }
    echo "Recordings past their retention date: $(sql "SELECT count(*)||' ('||pg_size_pretty(COALESCE(sum(r.bytes),0))||')' $expired_recordings")"
    test "$audit" = 1 && echo "Audit months older than $days days are dropped as whole months."
    confirm 'Delete them permanently? bastion stops briefly.'
    stop_app
    tool retain-recordings
    test "$audit" = 1 && tool retain-audit --offline --days "$days"
    restart_app
}

test -f compose.yaml || { echo 'Run this from the directory that holds compose.yaml.' >&2; exit 2; }
command=${1:-}
[ "$#" -gt 0 ] && shift
# --yes skips the confirmation prompt; every other argument goes to the command.
assume_yes=0
for argument in "$@"; do
    shift
    if [ "$argument" = --yes ]; then assume_yes=1; else set -- "$@" "$argument"; fi
done
case "$command" in
    status) [ "$#" -eq 0 ] || usage 2; status ;;
    partition-audit) [ "$#" -eq 0 ] || usage 2; partition_audit ;;
    clean) clean "$@" ;;
    -h|--help|help|'') usage ;;
    *) usage 2 ;;
esac

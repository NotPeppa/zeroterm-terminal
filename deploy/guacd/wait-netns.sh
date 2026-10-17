#!/bin/sh
# guacd start gate: run guacd only after netns-guard.sh has installed the egress rules in THIS network
# namespace. The marker holds the namespace identity, so a stale marker from an earlier start never passes.
# If the guard restarts (new namespace, new marker), stop so the restart policy rejoins the new namespace.
set -eu
here=$(readlink /proc/self/ns/net)
ready() { [ "$(cat /run/zt-netns/ready 2>/dev/null)" = "$here" ]; }
tries=0
until ready; do
    tries=$((tries + 1))
    if [ "$tries" -gt 300 ]; then
        echo 'guacd egress guard is not ready in this network namespace; refusing to start' >&2
        exit 1
    fi
    sleep 0.1
done
/usr/local/sbin/guacd "$@" &
pid=$!
trap 'kill "$pid" 2>/dev/null; wait "$pid"; exit 0' TERM INT
while kill -0 "$pid" 2>/dev/null; do
    if ! ready; then
        echo 'guacd egress guard restarted; leaving this network namespace' >&2
        kill "$pid" 2>/dev/null
        exit 1
    fi
    sleep 2 &
    wait $! || true
done
wait "$pid"

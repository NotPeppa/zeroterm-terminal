#!/bin/sh
# Owns guacd's network namespace (guacd joins it with network_mode: service:guacd-net) and installs the
# egress rules inside that namespace, so they are recreated with the container on every start instead of
# living on the host. Runs as root with only NET_ADMIN; guacd itself keeps no capabilities and cannot
# change them. When the rules are in place it records this namespace's identity for guacd's start gate.
set -eu
app=${ZT_APP_IP:?ZT_APP_IP must be the app container address on the guacd bridge}
marker=/run/zt-netns/ready
rm -f "$marker"

# guacd may only answer the app on 4822 and connect back to the app's per-session listener, which the
# app binds in the kernel ephemeral range. Docker's embedded DNS (127.0.0.11) is refused: guacd gets IPs.
iptables-restore <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -s $app/32 -p tcp --dport 4822 -j ACCEPT
-A OUTPUT -d 127.0.0.11/32 -j DROP
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -d $app/32 -p tcp --dport 32768:60999 -j ACCEPT
COMMIT
EOF
ip6tables-restore <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
COMMIT
EOF

iptables -S OUTPUT | grep -qx -- '-P OUTPUT DROP'
readlink /proc/self/ns/net > "$marker"
echo "guacd egress rules installed in $(cat "$marker"); only $app tcp/32768-60999 is reachable"
trap 'exit 0' TERM INT
while :; do sleep 3600 & wait $!; done

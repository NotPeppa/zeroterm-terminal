#!/bin/sh
set -eu
ssh-keygen -A
ssh-keygen -q -t ed25519 -N '' -f /var/log/fixture/wrong-host-key
ssh-keygen -q -t ed25519 -N '' -f /var/log/fixture/client-key
ssh-keygen -q -t ed25519 -a 4 -N 'fictional-key-passphrase' -f /var/log/fixture/client-ed25519-encrypted
ssh-keygen -q -t rsa -b 3072 -N '' -f /var/log/fixture/client-rsa
ssh-keygen -q -t rsa -b 3072 -a 4 -N 'fictional-key-passphrase' -f /var/log/fixture/client-rsa-encrypted
install -d -m 700 -o fixture -g fixture /home/fixture/.ssh
install -m 600 -o fixture -g fixture /var/log/fixture/client-key.pub /home/fixture/.ssh/authorized_keys
cat /var/log/fixture/client-ed25519-encrypted.pub /var/log/fixture/client-rsa.pub /var/log/fixture/client-rsa-encrypted.pub >> /home/fixture/.ssh/authorized_keys
/usr/sbin/sshd -D -E /var/log/fixture/sshd.log -o LogLevel=VERBOSE -o HostKey=/etc/ssh/ssh_host_ed25519_key -o PasswordAuthentication=yes -o PermitRootLogin=no &
# Real xrdp TLS, never the unencrypted RDP security layer.
sed -i 's/^security_layer=.*/security_layer=tls/; s/^certificate=.*/certificate=\/certs\/leaf.pem/; s/^key_file=.*/key_file=\/certs\/leaf.key/' /etc/xrdp/xrdp.ini
chmod 644 /certs/leaf.pem
chgrp xrdp /certs/leaf.key
chmod 640 /certs/leaf.key
/usr/sbin/xrdp-sesman --nodaemon >/var/log/fixture/sesman.stdout 2>&1 &
/usr/sbin/xrdp --nodaemon >/var/log/fixture/xrdp.stdout 2>&1 &
printf 'testpass\n' | tigervncpasswd -f > /var/log/fixture/vnc-password
chmod 600 /var/log/fixture/vnc-password
Xtigervnc :99 -geometry 1024x768 -depth 24 -rfbport 5901 -localhost no \
    -SecurityTypes None -UseIPv6=0 -AlwaysShared=1 >/var/log/fixture/vnc-none.log 2>&1 &
Xtigervnc :100 -geometry 1024x768 -depth 24 -rfbport 5902 -localhost no \
    -SecurityTypes VncAuth -PasswordFile /var/log/fixture/vnc-password -UseIPv6=0 \
    -AlwaysShared=1 >/var/log/fixture/vnc-password.log 2>&1 &
for n in 1 2 3 4 5; do
    test -S /tmp/.X11-unix/X99 && test -S /tmp/.X11-unix/X100 && break
    sleep 1
done
xterm -display :99 -geometry 80x24+0+0 -bg navy -fg white -title ZT-VNC-None \
    -e sh -c 'printf "ZT real VNC None fixture\n"; exec sh' >/var/log/fixture/vnc-none-terminal.log 2>&1 &
xterm -display :100 -geometry 80x24+0+0 -bg darkgreen -fg white -title ZT-VNC-Password \
    -e sh -c 'printf "ZT real VNC password fixture\n"; exec sh' >/var/log/fixture/vnc-password-terminal.log 2>&1 &
wait

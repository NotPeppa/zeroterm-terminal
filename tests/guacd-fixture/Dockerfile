FROM debian:bookworm-slim
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server xrdp xorgxrdp xserver-xorg-core xterm tigervnc-standalone-server tigervnc-tools \
    python3 openssl iproute2 procps xfonts-base xclip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/sh fixture \
    && printf 'fixture:fictional-Guac-pass-123\n' | chpasswd \
    && mkdir -p /run/sshd /run/xrdp /var/log/fixture \
    && printf '#!/bin/sh\nexec xterm -geometry 80x24 -title Guacamole-fixture\n' > /home/fixture/.xsession \
    && chmod 700 /home/fixture/.xsession && chown fixture:fixture /home/fixture/.xsession
RUN useradd -m -s /bin/sh badpassfixture \
    && printf 'badpassfixture:fictional-Guac-pass-123\n' | chpasswd
# xterm has no Ctrl+Shift+V binding by default; exercise the real X clipboard explicitly.
RUN printf '\n*VT100.Translations: #override Ctrl Shift <Key>V: insert-selection(CLIPBOARD)\n*VT100.utf8: 2\n*locale: false\n' >> /etc/X11/app-defaults/XTerm
RUN for name in fixture2 fixture3; do \
        useradd -m -s /bin/sh "$name" \
        && printf '%s:fictional-Guac-pass-123\n' "$name" | chpasswd \
        && cp /home/fixture/.xsession "/home/$name/.xsession" \
        && chown "$name:$name" "/home/$name/.xsession"; \
    done
COPY tests/guacd-fixture/start.sh /usr/local/bin/start-fixture
RUN chmod 755 /usr/local/bin/start-fixture
ENTRYPOINT ["/usr/local/bin/start-fixture"]

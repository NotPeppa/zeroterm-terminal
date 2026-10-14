FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config autoconf automake libtool-bin python3 curl ca-certificates \
    libssl-dev libcairo2-dev libjpeg62-turbo-dev libpng-dev libuuid1 uuid-dev \
    libpango1.0-dev libssh2-1-dev libvncserver-dev libwebp-dev libpulse-dev \
    libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Official immutable tag archives, SHA-256 checked before extraction.
COPY deploy/guacd/freerdp-no-redirect.py /src/freerdp-no-redirect.py
RUN curl -fL https://codeload.github.com/FreeRDP/FreeRDP/tar.gz/refs/tags/2.11.7 -o freerdp.tar.gz \
    && echo '22dbeeaad065e93f152d70e04ec8eeab08aa32c406a96be64f252526623625a4  freerdp.tar.gz' | sha256sum -c - \
    && tar xzf freerdp.tar.gz \
    && python3 /src/freerdp-no-redirect.py /src/FreeRDP-2.11.7 \
    && cmake -S FreeRDP-2.11.7 -B freerdp-build -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local -DWITH_X11=OFF -DWITH_WAYLAND=OFF \
        -DWITH_SERVER=OFF -DWITH_CLIENT=ON -DWITH_CLIENT_INTERFACE=ON \
        -DWITH_PULSE=OFF -DWITH_ALSA=OFF -DWITH_CUPS=OFF -DWITH_FFMPEG=OFF \
        -DWITH_MANPAGES=OFF -DBUILD_TESTING=OFF -DWITH_SSE2=ON -DCHANNEL_URBDRC=OFF \
    && cmake --build freerdp-build --parallel 1 \
    && cmake --install freerdp-build && ldconfig
RUN curl -fL https://codeload.github.com/apache/guacamole-server/tar.gz/refs/tags/1.6.0 -o guacamole.tar.gz \
    && echo '913b05d19beabed4a3066e6e2be3078783048f55c7a9d2e3a012897a8766c245  guacamole.tar.gz' | sha256sum -c - \
    && tar xzf guacamole.tar.gz
COPY deploy/guacd/apply-strict-pin.py deploy/guacd/zt-strict-pin.h deploy/guacd/zt-target-ready.h deploy/guacd/zt-ssh-host-key.h /src/patch/
COPY deploy/guacd/clipboard-unicode.py /src/patch/clipboard-unicode.py
RUN python3 /src/patch/apply-strict-pin.py /src/guacamole-server-1.6.0 \
    && python3 /src/patch/clipboard-unicode.py /src/guacamole-server-1.6.0 \
    && cd /src/guacamole-server-1.6.0 && autoreconf -fi \
    && PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure --prefix=/usr/local \
        --disable-guacenc --disable-guaclog --disable-kubernetes --disable-telnet \
    && make -j1 && make install && ldconfig \
    && guacd -v && test "$(pkg-config --modversion freerdp2)" = 2.11.7

COPY tests/guacd_clipboard_unicode.c /src/tests/guacd_clipboard_unicode.c
RUN cc -Wall -Wextra -Werror -Wno-unused-parameter -Wno-old-style-declaration \
    -I/src/guacamole-server-1.6.0/src/common \
    -I/src/guacamole-server-1.6.0 -I/usr/local/include \
    /src/tests/guacd_clipboard_unicode.c /src/guacamole-server-1.6.0/src/common/iconv.c \
    -L/usr/local/lib -lguac -o /src/clipboard-unicode-test && /src/clipboard-unicode-test

COPY tests/guacd_pin_unit.py /src/tests/guacd_pin_unit.py
RUN ulimit -c 0 && ZT_PIN_INCLUDE=/src/patch python3 /src/tests/guacd_pin_unit.py
COPY tests/ssh_host_key_methods.c /src/tests/ssh_host_key_methods.c
RUN cc -Wall -Wextra -Werror -I/src/patch /src/tests/ssh_host_key_methods.c -o /src/ssh-host-key-test \
    && /src/ssh-host-key-test
COPY tests/guacd-fixture/redirect.c /src/tests/redirect.c
RUN cc -Wall -Wextra -Werror /src/tests/redirect.c -o /src/zt-rdp-redirect-fixture \
    $(pkg-config --cflags --libs freerdp2 winpr2)

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libcairo2 libjpeg62-turbo libpng16-16 libuuid1 libpango-1.0-0 \
    libssh2-1 libvncclient1 libwebp7 libpulse0 libavcodec59 libavformat59 \
    libavutil57 libswscale6 ca-certificates fonts-dejavu-core fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10002 guacd && useradd -u 10002 -g guacd -M -s /usr/sbin/nologin guacd
COPY --from=build /usr/local/ /usr/local/
COPY --from=build /src/guacamole-server-1.6.0/LICENSE /src/guacamole-server-1.6.0/NOTICE /usr/share/doc/guacd/
RUN ldconfig && printf '%s\n' 'guacd=1.6.0' 'freerdp=2.11.7' 'rdp_arg=zt-strict-cert-pin' 'required_arg=zt-target-ready' 'ssh_arg=zt-ssh-display-only' 'patch=zt-pin-v5-clipboard-unicode' \
    'production_ready=false' > /usr/share/doc/guacd/zeroterm-capabilities
ENV HOME=/tmp LANG=C.UTF-8 LC_ALL=C.UTF-8
USER 10002:10002
EXPOSE 4822
ENTRYPOINT ["/usr/local/sbin/guacd"]
CMD ["-f", "-b", "0.0.0.0", "-l", "4822", "-L", "info"]

FROM runtime AS redirect-fixture
COPY --from=build /src/zt-rdp-redirect-fixture /usr/local/bin/zt-rdp-redirect-fixture

FROM runtime AS final

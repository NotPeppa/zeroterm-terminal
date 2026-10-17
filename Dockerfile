FROM node:24-bookworm-slim AS web-build
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM rust:1.95-bookworm AS server-build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY migrations/ ./migrations/
COPY tests/pg_fixture.rs ./tests/pg_fixture.rs
# Serialize the expensive web/Rust stages on the authorized low-memory host.
COPY --from=web-build /app/web/dist/ /app/web-dist/
ARG CARGO_BUILD_JOBS=1
ARG CACHE_NAMESPACE=zt-guac-v2
RUN --mount=type=cache,id=${CACHE_NAMESPACE}-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=${CACHE_NAMESPACE}-cargo-target,target=/app/target,sharing=locked \
    cargo build --release --locked -p bastion-server --jobs "$CARGO_BUILD_JOBS" \
    && cp /app/target/release/bastion-server /app/bastion-server

FROM server-build AS acceptance-build
ARG CACHE_NAMESPACE=zt-guac-v2
RUN --mount=type=cache,id=${CACHE_NAMESPACE}-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=${CACHE_NAMESPACE}-cargo-target,target=/app/target,sharing=locked \
    cargo test --release --locked --workspace --jobs 1 \
    && cargo build --release --locked -p bastion-store --example local_pg_acceptance --jobs 1 \
    && cargo test --release --locked --workspace --no-run --jobs 1 --message-format=json > /app/compiled-tests.json \
    && mkdir /app/testbin \
    && cp /app/target/release/examples/local_pg_acceptance /app/testbin/ \
    && python3 -c 'import json,shutil; artifacts=map(json.loads,open("/app/compiled-tests.json")); [shutil.copy2(a["executable"],"/app/testbin/") for a in artifacts if a.get("reason")=="compiler-artifact" and a.get("executable") and a["target"]["kind"]==["test"] and a["target"]["name"] in ("postgres","websocket","web_sessions","lifecycle","implicit_access","user_deletion","audit_partitions","asset_groups")]'

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libgcc-s1 openssh-client postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 bastion \
    && useradd --uid 10001 --gid bastion --no-create-home \
        --home-dir /var/lib/zeroterm-bastion --shell /usr/sbin/nologin bastion \
    && install -d -o bastion -g bastion -m 700 \
        /etc/zeroterm-bastion/secrets /run/bastion-db /run/bastion-runtime \
        /var/lib/zeroterm-bastion/recordings
COPY --from=server-build /app/bastion-server /usr/local/bin/bastion-server
COPY --from=server-build /app/web-dist/ /opt/zeroterm-bastion/web/dist/
COPY deploy/docker-init.sh deploy/docker-fresh-init.sh deploy/docker-runtime-role.sh \
     /usr/local/share/zeroterm-bastion/
RUN sed -i 's/\r$//' /usr/local/share/zeroterm-bastion/*.sh
USER 10001:10001
WORKDIR /var/lib/zeroterm-bastion
# HTTPS is published only by the co-located TLS reverse proxy.
ENTRYPOINT ["bastion-server"]
CMD ["serve", "--config", "/etc/zeroterm-bastion/production.toml"]

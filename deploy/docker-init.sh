#!/bin/sh
# Fresh schema-family-2 installation only. Never convert/reinitialize old volumes.
set -eu
umask 077
set -C
secret_dir=/etc/zeroterm-bastion/secrets
owner_dir=/run/bastion-db
runtime_dir=/run/bastion-runtime
database_name=${BASTION_DATABASE_NAME:-bastion}
case "$database_name" in ''|*[!a-zA-Z0-9_]*) echo 'Invalid database name' >&2; exit 1 ;; esac
if [ "$#" -ne 0 ]; then
    echo 'Fresh initialization takes no arguments; legacy conversion is unsupported.' >&2
    exit 1
fi
for directory in "$secret_dir" "$owner_dir" "$runtime_dir"; do
    test -d "$directory"
    if [ -n "$(find "$directory" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        echo 'Existing secrets found; refusing to overwrite or convert.' >&2
        exit 1
    fi
    chmod 700 "$directory"
done
# init generates only independent KEK material in browser-only schema family 2.
bastion-server init --directory "$secret_dir"
test -s "$secret_dir/kek-v1"
test ! -e "$secret_dir/api-token"
test ! -e "$secret_dir/ssh_host_ed25519_key"
for role in owner runtime; do
    password=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
    test "${#password}" -eq 64
    if [ "$role" = owner ]; then directory=$owner_dir; username=bastion;
    else directory=$runtime_dir; username=bastion_runtime; fi
    printf '%s\n' "$password" > "$directory/password"
    printf 'postgresql://%s:%s@postgres:5432/%s\n' "$username" "$password" "$database_name" > "$directory/database-url"
    chmod 600 "$directory/password" "$directory/database-url"
    unset password
done
echo 'Fresh secrets initialized; migrate and grant-runtime run as one-shot services, then create an administrator with create-admin.'

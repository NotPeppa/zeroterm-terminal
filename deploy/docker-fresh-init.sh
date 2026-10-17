#!/bin/sh
# One-shot initialization for `docker compose up` on a fresh installation.
#
# docker-init.sh deliberately refuses to run twice, because overwriting secrets would destroy the KEK and
# make every stored credential and recording unreadable. This wrapper only skips when all three secret
# directories are already populated, so `up` stays repeatable without ever re-initializing.
set -eu

secret_dir=/etc/zeroterm-bastion/secrets
owner_dir=/run/bastion-db
runtime_dir=/run/bastion-runtime

populated() {
    test -d "$1" && test -n "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)"
}

if populated "$secret_dir" && populated "$owner_dir" && populated "$runtime_dir"; then
    echo 'Secrets already initialized; nothing to do.'
    exit 0
fi

exec sh /usr/local/share/zeroterm-bastion/docker-init.sh

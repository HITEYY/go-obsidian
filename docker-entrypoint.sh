#!/bin/sh
set -e

# Remove stale LOCK files left by a previous unclean shutdown.
# Geth uses Go's flock-based LOCK file in the datadir; if the container is
# killed (OOM, docker stop, etc.) the file may persist and block the next run.
#
# At container start there is guaranteed to be NO other geth process holding
# the lock, so it is always safe to remove it here.

DATADIR="${GETH_DATADIR:-/root/.ethereum}"

for lockfile in \
    "$DATADIR/LOCK" \
    "$DATADIR/geth/chaindata/LOCK" \
    "$DATADIR/geth/lightchaindata/LOCK" \
    "$DATADIR/geth/nodekey/LOCK"; do
    if [ -f "$lockfile" ]; then
        echo "docker-entrypoint: removing stale lock file: $lockfile"
        rm -f "$lockfile"
    fi
done

# Also handle custom --datadir passed as arguments
for arg in "$@"; do
    case "$arg" in
        --datadir=*)
            CUSTOM_DATADIR="${arg#--datadir=}"
            for lockfile in \
                "$CUSTOM_DATADIR/LOCK" \
                "$CUSTOM_DATADIR/geth/chaindata/LOCK" \
                "$CUSTOM_DATADIR/geth/lightchaindata/LOCK" \
                "$CUSTOM_DATADIR/geth/nodekey/LOCK"; do
                if [ -f "$lockfile" ]; then
                    echo "docker-entrypoint: removing stale lock file: $lockfile"
                    rm -f "$lockfile"
                fi
            done
            ;;
    esac
done

exec geth "$@"

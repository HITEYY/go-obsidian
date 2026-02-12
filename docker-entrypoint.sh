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

# Default: bind HTTP and WS RPC to all interfaces so they are reachable
# from outside the container.  Users can still override via explicit flags.
HTTP_ADDR_SET=false
WS_ADDR_SET=false
for arg in "$@"; do
    case "$arg" in
        --http.addr|--http.addr=*) HTTP_ADDR_SET=true ;;
        --ws.addr|--ws.addr=*)     WS_ADDR_SET=true ;;
    esac
done

EXTRA_FLAGS=""
if [ "$HTTP_ADDR_SET" = false ]; then
    EXTRA_FLAGS="$EXTRA_FLAGS --http.addr 0.0.0.0"
fi
if [ "$WS_ADDR_SET" = false ]; then
    EXTRA_FLAGS="$EXTRA_FLAGS --ws.addr 0.0.0.0"
fi

# shellcheck disable=SC2086
exec geth $EXTRA_FLAGS "$@"

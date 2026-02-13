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
HTTP_VHOSTS_SET=false
HTTP_CORSDOMAIN_SET=false
WS_ORIGINS_SET=false
for arg in "$@"; do
    case "$arg" in
        --http.addr|--http.addr=*)               HTTP_ADDR_SET=true ;;
        --ws.addr|--ws.addr=*)                   WS_ADDR_SET=true ;;
        --http.vhosts|--http.vhosts=*)           HTTP_VHOSTS_SET=true ;;
        --http.corsdomain|--http.corsdomain=*)   HTTP_CORSDOMAIN_SET=true ;;
        --ws.origins|--ws.origins=*)             WS_ORIGINS_SET=true ;;
    esac
done

if [ "$HTTP_ADDR_SET" = false ]; then
    set -- --http.addr 0.0.0.0 "$@"
fi
if [ "$WS_ADDR_SET" = false ]; then
    set -- --ws.addr 0.0.0.0 "$@"
fi
if [ "$HTTP_VHOSTS_SET" = false ]; then
    set -- --http.vhosts "*" "$@"
fi
if [ "$HTTP_CORSDOMAIN_SET" = false ]; then
    set -- --http.corsdomain "*" "$@"
fi
if [ "$WS_ORIGINS_SET" = false ]; then
    set -- --ws.origins "*" "$@"
fi

exec geth "$@"

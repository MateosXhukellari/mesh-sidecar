#!/usr/bin/env bash
# Starts the stack with short-lived certs and runs every attack case.
# Prints PASS/FAIL per case; exits non-zero if any case FAILED.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --bins -q

tok() { openssl rand -hex 32; }
ORDERS=$(tok) PAYMENTS=$(tok) ANALYTICS=$(tok) LIAR=$(tok) RENEW=$(tok) EXPIRE=$(tok)

umask 077
cat > tokens.toml <<TOML
[[token]]
value = "$ORDERS"
identity = "spiffe://mesh/orders"

[[token]]
value = "$PAYMENTS"
identity = "spiffe://mesh/payments"

[[token]]
value = "$ANALYTICS"
identity = "spiffe://mesh/analytics"

[[token]]
value = "$LIAR"
identity = "spiffe://mesh/analytics"

[[token]]
value = "$RENEW"
identity = "spiffe://mesh/orders"

[[token]]
value = "$EXPIRE"
identity = "spiffe://mesh/orders"
TOML

LOG=$(mktemp -d)/stack.log
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

wait_port() {
  for _ in $(seq 50); do
    (echo > "/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  echo "port $1 never opened; see $LOG" >&2; exit 1
}

# 6s certs, so the expired-cert case only waits a few seconds.
MESH_CERT_TTL_SECS=6 ./target/debug/ca >>"$LOG" 2>&1 & pids+=($!)
wait_port 9100; wait_port 9101
./target/debug/backend >>"$LOG" 2>&1 & pids+=($!)
MESH_TOKEN=$PAYMENTS ./target/debug/inbound  >>"$LOG" 2>&1 & pids+=($!)
MESH_TOKEN=$ORDERS   ./target/debug/outbound >>"$LOG" 2>&1 & pids+=($!)
wait_port 9443; wait_port 9000   # sidecars bind only after enrolling

ANALYTICS_TOKEN=$ANALYTICS LIAR_TOKEN=$LIAR RENEW_TOKEN=$RENEW EXPIRE_TOKEN=$EXPIRE \
USED_TOKEN=$ORDERS ./target/debug/attack
echo "(stack log: $LOG)"

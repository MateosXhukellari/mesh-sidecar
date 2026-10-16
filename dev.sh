#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

cargo build --bins -q

# Fresh single-use tokens on every run.
ORDERS_TOKEN=$(openssl rand -hex 32)
PAYMENTS_TOKEN=$(openssl rand -hex 32)

umask 077   # tokens.toml is created readable by you only
cat > tokens.toml <<EOF
[[token]]
value = "$ORDERS_TOKEN"
identity = "spiffe://mesh/orders"

[[token]]
value = "$PAYMENTS_TOKEN"
identity = "spiffe://mesh/payments"
EOF

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

./target/debug/ca & pids+=($!)

# Wait until the CA is listening before the sidecars try to enroll.
for _ in $(seq 50); do
  (echo > /dev/tcp/127.0.0.1/9100) 2>/dev/null && break
  sleep 0.1
done

./target/debug/backend & pids+=($!)
MESH_TOKEN=$PAYMENTS_TOKEN ./target/debug/inbound  & pids+=($!)
MESH_TOKEN=$ORDERS_TOKEN   ./target/debug/outbound & pids+=($!)

wait -n   # if any process dies, fall through to cleanup and stop everything
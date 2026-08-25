#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

PID_A=
PID_B=
cleanup() {
  local status=$?
  stop_process "$PID_A"
  stop_process "$PID_B"
  delete_namespaces product-a product-b
  exit "$status"
}
trap cleanup EXIT

product_cli() {
  local namespace=$1 node=$2
  shift 2
  ip netns exec "$namespace" ironet \
    --config "/state/$node/config.toml" \
    --socket "/state/$node/control.sock" \
    --state-dir "/state/$node" \
    "$@"
}

ping_fails() {
  ! ip netns exec product-b ping -c 1 -W 1 -I "$ADDRESS_B" "$ADDRESS_A" >/dev/null 2>&1
}

echo "==> creating a two-machine underlay"
create_namespace product-a
create_namespace product-b
create_veth product-a product-a0 172.31.50.1/24 product-b product-b0 172.31.50.2/24
mkdir -p /state/node-a /state/node-b

echo "==> creating a network through the product CLI"
CREATE_JSON=$(product_cli product-a node-a network create production-demo \
  --node-name edge-a \
  --address-pool 198.23.0.0/16 \
  --listen 0.0.0.0:4000 \
  --no-dns \
  --no-start \
  --output json)
jq -e '
  .service_started == false and
  .network.created == true and
  .network.network == "production-demo" and
  .network.node == "edge-a" and
  (.network.endpoint_id | length > 0) and
  (.network.address | endswith("/32")) and
  (.network.addresses | length == 2) and
  (any(.network.addresses[]; endswith("/32"))) and
  (any(.network.addresses[]; endswith("/128"))) and
  .network.dns_domain == null
' <<<"$CREATE_JSON" >/dev/null
NETWORK_ID=$(jq -r '.network.network_id' <<<"$CREATE_JSON")
ADDRESS_A=$(jq -r '.network.address | split("/")[0]' <<<"$CREATE_JSON")
ADDRESS_A6=$(jq -r '.network.addresses[] | select(endswith("/128")) | split("/")[0]' <<<"$CREATE_JSON")

# The authority owns the network-wide visible QUIC profile. Make it
# deliberately non-default before issuing the invite so this integration test
# proves the signed payload distributes generation and pool to the joiner.
cat >>/state/node-a/config.toml <<'EOF'

[cover]
sni_pool = ["edge-video.example", "origin-video.example"]
profile_id = 17
EOF
product_cli product-a node-a seal-config >/dev/null

echo "==> issuing and consuming a signed invite"
INVITE_JSON=$(product_cli product-a node-a invite create \
  --address 172.31.50.1:4000 \
  --expires 10m \
  --output json)
INVITE_ID=$(jq -r '.id' <<<"$INVITE_JSON")
INVITE_TOKEN=$(jq -r '.token' <<<"$INVITE_JSON")
test -n "$INVITE_ID"
[[ $INVITE_TOKEN == ironet://join/v2/* ]]

JOIN_JSON=$(product_cli product-b node-b join "$INVITE_TOKEN" \
  --node-name edge-b \
  --no-start \
  --output json)
jq -e --arg network_id "$NETWORK_ID" '
  .service_started == false and
  .network.created == false and
  .network.network == "production-demo" and
  .network.network_id == $network_id and
  .network.node == "edge-b" and
  (.network.address | endswith("/32")) and
  (.network.addresses | length == 2) and
  (any(.network.addresses[]; endswith("/32"))) and
  (any(.network.addresses[]; endswith("/128"))) and
  .network.dns_domain == null
' <<<"$JOIN_JSON" >/dev/null
ENDPOINT_B=$(jq -r '.network.endpoint_id' <<<"$JOIN_JSON")
ADDRESS_B=$(jq -r '.network.address | split("/")[0]' <<<"$JOIN_JSON")
ADDRESS_B6=$(jq -r '.network.addresses[] | select(endswith("/128")) | split("/")[0]' <<<"$JOIN_JSON")
test "$ADDRESS_A" != "$ADDRESS_B"
test "$ADDRESS_A6" != "$ADDRESS_B6"
for config in /state/node-a/config.toml /state/node-b/config.toml; do
  python3 - "$config" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as source:
    cover = tomllib.load(source)["cover"]
assert cover == {
    "sni_pool": ["edge-video.example", "origin-video.example"],
    "profile_id": 17,
}
PY
done

echo "==> starting both daemons from generated state"
start_daemon product-a node-a PID_A
start_daemon product-b node-b PID_B
wait_until "creator readiness" ctl product-a node-a health
wait_until "joiner readiness" ctl product-b node-b health
wait_until "product overlay connectivity" \
  ip netns exec product-b ping -c 1 -W 3 -I "$ADDRESS_B" "$ADDRESS_A"
ip netns exec product-a ping -c 3 -W 3 -I "$ADDRESS_A" "$ADDRESS_B"
ip netns exec product-a ping -6 -c 3 -W 3 -I "$ADDRESS_A6" "$ADDRESS_B6"

echo "==> verifying live status is V2-native telemetry"
for node_spec in "product-a node-a" "product-b node-b"; do
  read -r namespace node <<<"$node_spec"
  product_cli "$namespace" "$node" status --output json \
    | tee "/state/$node/status.json" \
    | jq -e '
        (has("capacities") | not) and
        (has("network") | not) and
        (has("dataplane") | not) and
        .mesh.enabled == true and
        .mesh.directory_entries == 2 and
        (.mesh.nodes | length == 2) and
        (all(.mesh.nodes[]; (.node_addresses | length) == 2)) and
        .gateway.subnet_nat_enabled == true and
        .gateway.transit_enabled == true and
        (.gateway.advertised_prefixes | length) == 0 and
        (.peers | length == 1) and
        (.peers[0] |
          .protocol_major == 2 and
          .traffic.tx_packets > 0 and .traffic.rx_packets > 0 and
          .traffic.trains_built > 0 and .traffic.cells_built > 0 and
          (has("delivery_tagged_packets") | not) and
          (has("tx_fragments") | not) and
          (has("fec_tx_recovery_shards") | not) and
          (has("capacity_probe_attempts") | not)
        )
      ' >/dev/null
done

product_cli product-a node-a metrics \
  | tee /state/node-a/metrics.prom \
  | awk '
      /^# TYPE ironet_v2_peer_tx_records_total counter$/ { type = 1 }
      /^ironet_v2_peer_tx_records_total\{/ && $2 + 0 > 0 { live = 1 }
      /^ironet_v2_gateway_subnet_nat_enabled 1$/ { nat = 1 }
      /^ironet_peer_/ { legacy = 1 }
      END { exit !(type && live && nat && !legacy) }
    '

echo "==> verifying that product vocabulary exposes the live network"
product_cli product-a node-a network show --output json \
  | tee /state/node-a/network-show.json \
  | jq -e --arg network_id "$NETWORK_ID" '.network.network_id == $network_id' >/dev/null
product_cli product-a node-a node list --output json \
  | tee /state/node-a/node-list.json \
  | jq -e --arg endpoint "$ENDPOINT_B" '
      length == 2 and
      any(.[]; .name == "edge-a" and .local == true) and
      any(.[]; .endpoint_id == $endpoint and .local == false and .removed == false)
    ' >/dev/null
product_cli product-b node-b node list --output json \
  | tee /state/node-b/node-list.json \
  | jq -e '
      length == 2 and
      any(.[]; .name == "edge-b" and .local == true) and
      any(.[]; .name == "edge-a" and .local == false and .removed == false)
    ' >/dev/null

echo "==> revoking the joining credential and proving reconnect is denied"
product_cli product-a node-a invite revoke "$INVITE_ID" --output json \
  | jq -e '.changed == true and .applied == true' >/dev/null
product_cli product-a node-a invite list --output json \
  | jq -e --arg id "$INVITE_ID" 'any(.[]; .id == $id and .revoked == true)' >/dev/null

stop_process "$PID_B"
PID_B=
wait_until "joiner disconnect" ping_fails
start_daemon product-b node-b PID_B
sleep 3
ping_fails

echo "product create/invite/join network-namespace test passed"

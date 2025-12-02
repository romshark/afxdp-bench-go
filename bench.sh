#!/usr/bin/env bash
set -euo pipefail

COUNT="${1:-1000000}"
ZFLAG="${2:-}"   # only "zc" enables zerocopy
IFACE_EGRESS="${3:-center_1}"
IFACE_INGRESS="${4:-top_2}"

get_stat() {
    ethtool -S "$1" | awk -v key="$2" '$1 == key":" { print $2 }'
}

get_stat_egress()  { get_stat "$IFACE_EGRESS" "$1"; }
get_stat_ingress() { get_stat "$IFACE_INGRESS" "$1"; }

go generate ./...
(go build ./cmd/bench)

# ---- Before ----
TX_PHY_BEFORE=$(get_stat_egress tx_packets_phy)
BYTES_PHY_BEFORE=$(get_stat_egress tx_bytes_phy)
RX_PHY_BEFORE=$(get_stat_ingress rx_packets_phy)
RX_BYTES_PHY_BEFORE=$(get_stat_ingress rx_bytes_phy)

# ---- Run benchmark ----
BENCH_ARGS=(
  -ie "$IFACE_EGRESS"
  -ii "$IFACE_INGRESS"
  -n "$COUNT"
)

# Only if ZFLAG == "zc"
if [[ "$ZFLAG" == "zc" ]]; then
    BENCH_ARGS+=(-z)
fi

(time sudo ./bench "${BENCH_ARGS[@]}")

# ---- After ----
TX_PHY_AFTER=$(get_stat_egress tx_packets_phy)
BYTES_PHY_AFTER=$(get_stat_egress tx_bytes_phy)
RX_PHY_AFTER=$(get_stat_ingress rx_packets_phy)
RX_BYTES_PHY_AFTER=$(get_stat_ingress rx_bytes_phy)

# ---- Report ----
echo "Requested TX:       $COUNT"

echo "Egress:"
echo "  tx_packets_phy delta: $((TX_PHY_AFTER   - TX_PHY_BEFORE))"
echo "  tx_bytes_phy   delta: $((BYTES_PHY_AFTER - BYTES_PHY_BEFORE))"

echo "Ingress:"
echo "  rx_packets_phy delta: $((RX_PHY_AFTER    - RX_PHY_BEFORE))"
echo "  rx_bytes_phy   delta: $((RX_BYTES_PHY_AFTER - RX_BYTES_PHY_BEFORE))"

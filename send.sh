#!/usr/bin/env bash
set -euo pipefail

COUNT="${1:-1000000}" # default if not provided
IFACE="${2:-center_1}"

DEST_MAC="58:a2:e1:04:a9:db" # top_2
QUEUE=0

# Helper: extract a single ethtool counter value
get_stat() {
    ethtool -S "$IFACE" | awk -v key="$1" '$1 == key":" { print $2 }'
}

go generate ./...
(go build ./cmd/send)

# Before
TX_PHY_BEFORE=$(get_stat tx_packets_phy)
BYTES_PHY_BEFORE=$(get_stat tx_bytes_phy)

(time sudo ./send \
  -i "$IFACE" \
  -d "$DEST_MAC" \
  -s 192.168.1.10 \
  -D 192.168.1.20 \
  -p 9000 \
  -n "$COUNT" \
  -q $QUEUE)

# After
TX_PHY_AFTER=$(get_stat tx_packets_phy)
BYTES_PHY_AFTER=$(get_stat tx_bytes_phy)

echo "Requested:          $COUNT"
echo "tx_packets_phy delta: $((TX_PHY_AFTER - TX_PHY_BEFORE))"
echo "tx_bytes_phy   delta: $((BYTES_PHY_AFTER - BYTES_PHY_BEFORE))"
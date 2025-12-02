#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "usage: $0 <num_packets>"
    exit 1
fi

COUNT="$1"
IF=center_1

# Helper: extract a single ethtool counter value
get_stat() {
    ethtool -S "$IF" | awk -v key="$1" '$1 == key":" { print $2 }'
}

# Before
TX_PHY_BEFORE=$(get_stat tx_packets_phy)
BYTES_PHY_BEFORE=$(get_stat tx_bytes_phy)

# Run your AF_XDP sender
./sendzc.sh "$COUNT"

# After
TX_PHY_AFTER=$(get_stat tx_packets_phy)
BYTES_PHY_AFTER=$(get_stat tx_bytes_phy)

echo "Requested:          $COUNT"
echo "tx_packets_phy delta: $((TX_PHY_AFTER - TX_PHY_BEFORE))"
echo "tx_bytes_phy   delta: $((BYTES_PHY_AFTER - BYTES_PHY_BEFORE))"
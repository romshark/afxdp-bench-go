#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-top_2}"

go generate ./...
(go build ./cmd/recv)
sudo ./recv -i "$IFACE" -z


#!/bin/bash
# Build the board-2.bin each radio's ath11k loads: linux-firmware's board files
# plus the U6-Enterprise's own from the stock firmware, appended under the
# variant names the board DTS selects (qcom,ath11k-calibration-variant).
#   fw/mk-board2.sh   -> fw/out/{IPQ5018,QCN9074}/board-2.bin (inputs from $BLOBS)
# ath11k-bdencoder is qca-swiss-army-knife's (ISC licence).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../site.conf.example
. "$here/../site.conf"
B=$(cd "$here/.." && cd "$BLOBS" && pwd)/wifi/board

build() { # <chip> <bus> <stock file>:<variant>...
	local chip=$1 bus=$2 o=$here/out/$1; shift 2
	rm -rf "$o"; mkdir -p "$o"
	cp "$B/linux-firmware/$chip"/* "$o/"
	for v in "$@"; do cp "$B/stock-a654/${v%%:*}" "$o/"; done
	python3 - "$o/board-2.json" "$bus" "$@" <<'PY'
import json, sys
path, bus, adds = sys.argv[1], sys.argv[2], sys.argv[3:]
j = json.load(open(path))
for a in adds:
    data, variant = a.split(':')
    j[0]['board'].append({'names': [f'bus={bus},qmi-chip-id=0,qmi-board-id=255,variant={variant}'], 'data': data})
json.dump(j, open(path, 'w'), indent=2)
PY
	(cd "$o" && python3 "$here/ath11k-bdencoder" -c board-2.json -o board-2.bin > /dev/null)
	echo "$chip: $(sha256sum "$o/board-2.bin" | cut -c1-16) $(python3 "$here/ath11k-bdencoder" -i "$o/board-2.bin" | grep -c 'variant=')"
}
build IPQ5018 ahb bdwlan.b23:Ubiquiti-U6-Enterprise
build QCN9074 pci bdwlan.ba3:Ubiquiti-U6-Enterprise-5G bdwlan.ba4:Ubiquiti-U6-Enterprise-6G

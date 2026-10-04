#!/bin/bash
# How many times a radio sends an unacknowledged probe response and action
# frame (OCE allows at most 3 retries of a probe response, 4 attempts): send
# <count> of each to an absent station with mgmtsend and read the firmware's
# over-the-air attempt counter (HTT stats type 1) around them, minus the
# background rate measured over the same time with nothing sent.
#   U6E_AP=<ap> test/oce-retry.sh <interface> [<count>]
set -uo pipefail
cd "$(dirname "$0")" || exit 1
. ./lib.sh
i=${1:?interface} n=${2:-200}
mkdir -p ../log
aarch64-linux-gnu-gcc -O2 -static -o ../log/mgmtsend mgmtsend.c || exit 1
ap_root 'cat > /run/mgmtsend && chmod 755 /run/mgmtsend' < ../log/mgmtsend
T=$((n / 10 + 60)) ap_root sh -s "$i" "$n" <<'AP'
i=$1 n=$2
# The radio's debugfs directory: pci-<address> for a PCI card, ahb-<node> for
# the SoC's own.
dev=$(readlink -f /sys/class/net/$i/device)
d=$(ls -d /sys/kernel/debug/ath11k/*-"${dev##*/}"/mac0 2>/dev/null) || { echo "$i: no ath11k debugfs" >&2; exit 1; }
echo 1 > $d/htt_stats_type
snap() { awk '/^num_total_ppdus_tried_ota/ {o = $3} /^tx_xretry/ {x = $3} END {print o, x}' $d/htt_stats; }
run() { # <probe|action|idle>
	set -- $(snap); o0=$1 x0=$2; t0=$(date +%s%N)
	if [ "$T" = idle ]; then sleep "$IDLE"; else /run/mgmtsend $i 02:00:00:5e:00:01 $T $n > /dev/null; fi
	t1=$(date +%s%N); set -- $(snap)
	echo "$T $(((t1 - t0) / 1000000)) $(($1 - o0)) $(($2 - x0))"
}
T=probe run > /run/r.probe
IDLE=$(awk '{printf "%.3f", $2 / 1000}' /run/r.probe)
T=idle run > /run/r.idle; T=action run > /run/r.action
awk -v n=$n 'FILENAME ~ /idle/ {ims = $2; io = $3} FILENAME !~ /idle/ {
	printf "%s: %.1f attempts per frame (%d ms, xretry %d)\n", $1, ($3 - io / ims * $2) / n, $2, $4 }' /run/r.idle /run/r.probe /run/r.action
rm -f /run/r.probe /run/r.idle /run/r.action /run/mgmtsend
AP

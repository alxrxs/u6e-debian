#!/bin/bash
# Capture on the test client's Wi-Fi card in monitor mode, then put it back in
# managed mode:
#   test/sniff.sh <MHz> <width> [<center MHz>] <seconds> <out.pcap>
# (iw's "set freq" arguments, e.g. 6375 160 6345, 5745 80 5775, 2472 HT20.)
# The card's P2P-device wdev counts as a running interface and makes cfg80211
# ignore a monitor interface's channel, so it is deleted first.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
[ $# -ge 4 ] || { sed -n '2,6p' "$0" >&2; exit 2; }
out=${*: -1} secs=${*: -2:1}
freq=("${@:1:$#-2}")
T=$((secs + 60)) client "N='sudo ip netns exec $TEST_NETNS'
phy=phy\$(\$N iw dev $TEST_IFACE info | awk '/wiphy/ {print \$2}')
p2p=\$(\$N iw dev | awk '/P2P-device/ {print w} {w = \$2}')
[ -z \"\$p2p\" ] || \$N iw wdev \$p2p del
\$N ip link set $TEST_IFACE down
\$N iw phy \$phy interface add u6emon type monitor &&
	\$N ip link set u6emon up &&
	\$N iw dev u6emon set freq ${freq[*]} &&
	\$N timeout $secs tcpdump -i u6emon -s 0 -w /run/u6e-test.pcap 2>/dev/null
\$N iw dev u6emon del
\$N ip link set $TEST_IFACE up"
client 'sudo cat /run/u6e-test.pcap; sudo rm -f /run/u6e-test.pcap' > "$out"
echo "$(tshark -r "$out" 2>/dev/null | wc -l) frames in $out"

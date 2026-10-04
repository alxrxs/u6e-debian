#!/bin/bash
# Join one of the site's SSIDs from the test client as its kind requires (sae:
# FT-SAE/SAE, ent: FT-EAP/EAP-SHA256 with wifi_test_eap's account, psk-mab:
# WPA2-PSK), get an address, ping the gateway 20 times, and report what the
# supplicant saw. PMF kinds enforce beacon protection, so a beacon that fails
# its MIC shows as a disconnect.
#   test/join.sh "<SSID>" [<BSSID>]
# KEYS=1 also prints the BIGTK (key ID and key), for test/bip-verify.py.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
ssid=${1:?SSID} bssid=${2:-}
kind=
for e in "${WIFI_SSIDS[@]}"; do
	IFS='|' read -r name k _ <<<"$e"
	[ "$name" = "$ssid" ] && kind=$k
done
[ -n "$kind" ] || { echo "$ssid is not in WIFI_SSIDS" >&2; exit 2; }
{
	printf 'ctrl_interface=/run/wpa_supplicant\ncountry=%s\nsae_pwe=1\nnetwork={\n\tssid="%s"\n' "$WIFI_COUNTRY" "$ssid"
	[ -z "$bssid" ] || printf '\tbssid=%s\n' "$bssid"
	case $kind in
	sae) printf '\tkey_mgmt=FT-SAE SAE\n\tieee80211w=2\n\tbeacon_prot=1\n\tsae_password="%s"\n' "$(wifi_psk "$ssid")" ;;
	ent)
		{ read -r id; read -r pw; } < <(wifi_test_eap)
		printf '\tkey_mgmt=FT-EAP WPA-EAP-SHA256\n\tieee80211w=2\n\tbeacon_prot=1\n\teap=PEAP\n\tphase2="auth=MSCHAPV2"\n'
		printf '\tidentity="%s"\n\tpassword="%s"\n\tca_cert="/run/u6e-test-ca.pem"\n' "$id" "$pw" ;;
	psk-mab) printf '\tkey_mgmt=WPA-PSK\n\tpsk="%s"\n' "$(wifi_psk "$ssid")" ;;
	esac
	echo '}'
} | client 'sudo sh -c "umask 077; cat > /run/u6e-test.conf"'
[ "$kind" != ent ] || wifi_eap_ca | client 'sudo sh -c "umask 077; cat > /run/u6e-test-ca.pem"'
# The log holds the keys (-K) while the test runs; it is deleted at the end.
client "N='sudo ip netns exec $TEST_NETNS'; I=$TEST_IFACE
sudo rm -f /run/u6e-test.log
\$N $TEST_SUPPLICANT -B -dd -K -i \$I -c /run/u6e-test.conf -P /run/u6e-test.pid -t -f /run/u6e-test.log || {
	echo 'wpa_supplicant did not start'; sudo rm -f /run/u6e-test.conf /run/u6e-test-ca.pem /run/u6e-test.log; exit 1; }
sleep 15
\$N ip addr flush dev \$I
\$N timeout 15 dhcpcd -4 -1 -w \$I >/dev/null 2>&1
echo \"address: \$(\$N ip -4 -br addr show \$I | awk '{print \$3}')\"
gw=\$(\$N ip route | awk '/default/ {print \$3; exit}')
[ -z \"\$gw\" ] || \$N ping -c 20 -W 2 \$gw | grep 'packet loss'
\$N wpa_cli -p /run/wpa_supplicant -i \$I status | grep -E '^(wpa_state|bssid|freq|key_mgmt|pairwise_cipher)=' | tr '\n' ' '; echo
echo \"connects \$(sudo grep -c CTRL-EVENT-CONNECTED /run/u6e-test.log) disconnects \$(sudo grep -c CTRL-EVENT-DISCONNECTED /run/u6e-test.log) unprotected beacons \$(sudo grep -c UNPROT-BEACON /run/u6e-test.log)\"
[ '${KEYS:-0}' = 0 ] || sudo sed -n 's/.*BIGTK in EAPOL-Key - hexdump(len=[0-9]*): //p' /run/u6e-test.log | tail -1 |
	awk '{k=\"\"; for (i = 15; i <= NF; i++) k = k \$i; print \"BIGTK key ID\", strtonum(\"0x\" \$7), \"key\", k}'
sudo kill \$(cat /run/u6e-test.pid)
\$N ip addr flush dev \$I
sudo rm -f /run/u6e-test.conf /run/u6e-test-ca.pem /run/u6e-test.log"

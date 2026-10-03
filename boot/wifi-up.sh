#!/bin/bash
# Start the test SSID on all three radios of the AP running our image, bridged
# into the client VLAN's bridge. The passphrase comes from the site's
# wifi_psk (site.conf) and only ever lands in /run on the AP.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
SSID=$(wifi_ssid) PSK=$(wifi_psk)

common="ctrl_interface=/run/hostapd
bridge=br$CLIENT_VLAN
ssid=$SSID
country_code=$WIFI_COUNTRY
ieee80211d=1
ieee80211h=1
wmm_enabled=1
ieee80211n=1
ieee80211ax=1
wpa=2
rsn_pairwise=CCMP
sae_password=$PSK"
mixed="wpa_key_mgmt=SAE WPA-PSK
wpa_passphrase=$PSK
ieee80211w=1"
sae="wpa_key_mgmt=SAE
sae_pwe=1
ieee80211w=2"

conf() { # <iface> <band lines>
	echo "cat > /run/hostapd-u6e/$1.conf <<'EOF'"
	printf 'interface=%s\n%s\n%s\n' "$1" "$common" "$2"
	echo "EOF"
}

{
	echo "mkdir -p /run/hostapd-u6e && chmod 700 /run/hostapd-u6e"
	# The radios regulate themselves (firmware default: US); move them to the
	# site's country before hostapd reads its channel list. ath11k only passes a
	# country to a radio's firmware once that radio is started, i.e. has an
	# interface up.
	echo "for i in wlan24 wlan5 wlan6; do ip link set \$i up; done
iw reg set $WIFI_COUNTRY
for _ in \$(seq 20); do [ \"\$(iw reg get | grep -c '^country $WIFI_COUNTRY')\" -ge 3 ] && break; sleep 0.5; done
iw reg get | grep -E '^(phy|country)' | paste - - | sed 's/^/reg: /'"
	# rnr: 2.4 and 5 GHz beacons announce the 6 GHz BSS (Reduced Neighbor
	# Report), which is how most clients find 6 GHz at all; hostapd only
	# reports a 6 GHz BSS it runs in the same process.
	conf wlan24 "$WIFI_24
$mixed
rnr=1"
	conf wlan5 "$WIFI_5
$mixed
rnr=1"
	# WPA3-only: 6 GHz admits nothing else.
	conf wlan6 "$WIFI_6
$sae"
	echo "chmod 600 /run/hostapd-u6e/*.conf"
	# A rerun stops the previous instance and waits until it has torn its BSSs
	# down: a radio that still has one refuses the new beacon.
	echo 'old=$(cat /run/hostapd-u6e/hostapd.pid 2>/dev/null)
if [ -n "$old" ] && kill "$old" 2>/dev/null; then
	for _ in $(seq 20); do kill -0 "$old" 2>/dev/null || break; sleep 0.5; done
fi
confs=
for i in wlan24 wlan5 wlan6; do
	[ -e /sys/class/net/$i ] && confs="$confs /run/hostapd-u6e/$i.conf" || echo "$i: no such radio"
done
hostapd -B -P /run/hostapd-u6e/hostapd.pid -f /run/hostapd-u6e/hostapd.log $confs || echo "hostapd failed"
sleep 8
for i in wlan24 wlan5 wlan6; do
	echo "== $i: $(hostapd_cli -p /run/hostapd -i $i status 2>/dev/null | grep -E "^(state|freq|channel|num_sta\[0\]|ssid\[0\])=" | tr "\n" " ")"
done'
} | T=120 ap_root sh

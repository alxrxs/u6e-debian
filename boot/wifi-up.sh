#!/bin/bash
# Start the test SSID on all three radios of the AP running our image, bridged
# into the client VLAN's bridge. The passphrase comes from the site's
# wifi_psk (site.conf) and only ever lands in /run on the AP.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
SSID=$(wifi_ssid) PSK=$(wifi_psk)
# 802.11r: every AP serving the SSID derives the same mobility domain from it.
MDID=$(printf %s "$SSID" | md5sum | cut -c1-4)

common="ctrl_interface=/run/hostapd
bridge=br$CLIENT_VLAN
ssid=$SSID
country_code=$WIFI_COUNTRY
ieee80211d=1
ieee80211h=1
local_pwr_constraint=0
spectrum_mgmt_required=1
wmm_enabled=1
uapsd_advertisement_enabled=1
ieee80211n=1
ieee80211ax=1
he_su_beamformer=1
he_su_beamformee=1
he_mu_beamformer=1
he_twt_responder=1
he_spr_sr_control=3
he_spr_non_srg_obss_pd_max_offset=10
wpa=2
rsn_pairwise=CCMP
sae_password=$PSK
group_mgmt_cipher=AES-128-CMAC
beacon_prot=1
mobility_domain=$MDID
ft_psk_generate_local=1
rrm_neighbor_report=1
rrm_beacon_report=1
bss_transition=1
wnm_sleep_mode=1
mbo=1
interworking=1
access_network_type=0
internet=1
qos_map_set=8,1,18,3,20,3,22,3,24,4,26,4,28,4,30,4,32,4,34,4,36,4,38,4,40,5,44,6,46,6,0,63,255,255,255,255,255,255,255,255,255,255,255,255,255,255"
# local_pwr_constraint + spectrum_mgmt_required: 802.11h (spectrum management,
# a 0 dB Power Constraint) outside DFS channels too, where hostapd sets it only
# on its own. qos_map_set: RFC 8325's DSCP to user priority mapping (CS6/CS7 stay best
# effort), so clients mark their uplink the way the network does.
mixed="wpa_key_mgmt=SAE WPA-PSK FT-SAE FT-PSK
wpa_passphrase=$PSK
ieee80211w=1"
sae="wpa_key_mgmt=SAE FT-SAE
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
nas_identifier=u6e-wlan24
he_bss_color=11
rnr=1"
	conf wlan5 "$WIFI_5
$mixed
nas_identifier=u6e-wlan5
he_bss_color=22
rnr=1"
	# WPA3-only: 6 GHz admits nothing else.
	conf wlan6 "$WIFI_6
$sae
nas_identifier=u6e-wlan6
he_bss_color=33"
	echo "chmod 600 /run/hostapd-u6e/*.conf"
	# A rerun stops the previous instance and waits until its BSSs are gone from
	# the radios, which outlast the process: a radio that still has one refuses
	# the new beacon.
	echo 'old=$(cat /run/hostapd-u6e/hostapd.pid 2>/dev/null)
if [ -n "$old" ] && kill "$old" 2>/dev/null; then
	for _ in $(seq 20); do kill -0 "$old" 2>/dev/null || break; sleep 0.5; done
fi
for _ in $(seq 20); do
	iw dev | grep -q "^[[:space:]]*ssid " || break
	sleep 0.5
done
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

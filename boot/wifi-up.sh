#!/bin/bash
# Start the test SSID on all three radios of the AP running our image, bridged
# into the client VLAN's bridge. The passphrase comes from the site's
# wifi_psk (site.conf) and only ever lands in /run on the AP.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
SSID=$(wifi_ssid) PSK=$(wifi_psk) FTKEY=$(wifi_ft_key)
# 802.11r: every AP serving the SSID derives the same mobility domain from it.
MDID=$(printf %s "$SSID" | md5sum | cut -c1-4)
# OCE IP Subnet Identifier: the same for every AP that serves this SSID on the
# client VLAN, without revealing the subnet
SUBNET_ID=$(printf '%s/%s' "$SSID" "$CLIENT_VLAN" | md5sum | cut -c1-12)

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
he_spr_sr_control=5
he_spr_non_srg_obss_pd_max_offset=10
wpa=2
rsn_pairwise=CCMP GCMP-256
sae_password=$PSK
group_mgmt_cipher=AES-128-CMAC
mobility_domain=$MDID
r0kh=ff:ff:ff:ff:ff:ff * $FTKEY
r1kh=00:00:00:00:00:00 00:00:00:00:00:00 $FTKEY
ft_over_ds=0
transition_disable=0x01
ocv=1
ssid_protection=1
stationary_ap=1
ftm_responder=1
rrm_neighbor_report=1
rrm_link_measurement_report=1
bss_transition=1
wnm_sleep_mode=1
proxy_arp=1
na_mcast_to_ucast=1
ap_isolate=1
multicast_to_unicast=1
wpa_strict_rekey=1
bss_load_update_period=50
esp=1
mbo=1
oce=4
oce_ip_subnet_id=$SUBNET_ID
enable_dscp_policy_capa=1
interworking=1
access_network_type=0
internet=1
qos_map_set=8,1,18,3,20,3,22,3,24,4,26,4,28,4,30,4,32,4,34,4,36,4,38,4,40,5,44,6,46,6,0,63,255,255,255,255,255,255,255,255,255,255,255,255,255,255"
# local_pwr_constraint + spectrum_mgmt_required: 802.11h (spectrum management,
# a 0 dB Power Constraint) outside DFS channels too, where hostapd sets it only
# on its own. qos_map_set: RFC 8325's DSCP to user priority mapping (CS6/CS7 stay best
# effort), so clients mark their uplink the way the network does.
# transition_disable: clients never fall back to WPA2 here; ocv (802.11-2020)
# and ssid_protection (802.11-2024) bind the channel and SSID into the key
# exchange; ft_over_ds=0 keeps 802.11r roaming over the air only;
# enable_dscp_policy_capa: Wi-Fi QoS Management DSCP policies (hostapd main). FT-SAE's
# PMK comes from each SAE exchange, so a radio pulls a roaming client's keys
# from the one it came from (r0kh/r1kh wildcards with one shared key); the
# R0KH-ID (nas_identifier) is unique per AP in the mobility domain.
# he_spr_sr_control=5: non-SRG OBSS-PD spatial reuse at
# he_spr_non_srg_obss_pd_max_offset (parameterized SR disallowed).
# SAE hash-to-element only (sae_pwe=1) on every band: 6 GHz admits no
# hunting-and-pecking, and every client here does H2E.
# ftm_responder: Fine Timing Measurement responder (802.11-2024 11.21.6), so
# clients can range to the AP for indoor location.
# oce=4: Wi-Fi Optimized Connectivity AP (hostapd answers the probes here);
# esp: Estimated Service Parameters, so clients can estimate their throughput.
# proxy_arp (802.11v): the bridge answers ARP and IPv6 neighbor solicitations
# for the clients, so broadcast ARP stays off the air; it hairpins client to
# client traffic, so ap_isolate leaves that forwarding to the bridge alone
# (otherwise multicast goes out twice). multicast_to_unicast: group frames
# (mDNS, SSDP, IPv6) reach each client as unicast at its own rate, not the
# basic rate. wpa_strict_rekey: a new group key whenever a client leaves.
# WPA3 on every band: 6 GHz admits nothing else, and clients (iOS) only treat
# the 6 GHz BSS as the same network when 2.4/5 GHz offer the same security.
# SAE-EXT-KEY (AKMs 24/25, WPA3 3.5) with GCMP-256 and SAE groups 20/21 next
# to SAE/CCMP: clients that support it use it, the rest keep SAE; group
# traffic stays CCMP-128 and BIP-CMAC-128, which every client supports.
sae="wpa_key_mgmt=SAE SAE-EXT-KEY FT-SAE FT-SAE-EXT-KEY
sae_groups=19 20 21
ieee80211w=2
sae_pwe=1"

# The radios' HT/VHT capabilities (iw phy): hostapd advertises only what is
# listed, and without them Wi-Fi 4/5 clients get no LDPC, STBC, short guard
# interval or beamforming. The site's ht_capab carries the channel width.
HT_CAPS="[LDPC][SHORT-GI-20][SHORT-GI-40][TX-STBC][RX-STBC1]"
VHT_CAPS_5="[MAX-MPDU-11454][RXLDPC][SHORT-GI-80][TX-STBC-2BY1][RX-STBC-1][SU-BEAMFORMER][SU-BEAMFORMEE][MU-BEAMFORMER][BF-ANTENNA-4][SOUNDING-DIMENSION-4][MAX-A-MPDU-LEN-EXP7][RX-ANTENNA-PATTERN][TX-ANTENNA-PATTERN]"
ht() { # <band lines> <capabilities>: append them to the site's ht_capab
	if grep -q '^ht_capab=' <<<"$1"; then
		sed "s/^ht_capab=.*/&$2/" <<<"$1"
	else
		printf '%s\nht_capab=%s\n' "$1" "$2"
	fi
}

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
	# reports a 6 GHz BSS it runs in the same process. 2.4 GHz is OFDM only, so
	# beacons and management frames go at 6 Mbit/s rather than 1 (Wi-Fi Optimized
	# Connectivity wants at least 5.5).
	conf wlan24 "$(ht "$WIFI_24" "$HT_CAPS")
$sae
nas_identifier=${AP}-wlan24
he_bss_color=11
supported_rates=60 90 120 180 240 360 480 540
basic_rates=60 120 240
rnr=1"
	conf wlan5 "$(ht "$WIFI_5" "${HT_CAPS}[MAX-AMSDU-7935]")
vht_capab=$VHT_CAPS_5
$sae
nas_identifier=${AP}-wlan5
he_bss_color=22
rnr=1"
	# FILS Discovery (802.11ai) every 20 ms between beacons speeds up 6 GHz
	# scans.
	conf wlan6 "$WIFI_6
$sae
nas_identifier=${AP}-wlan6
he_bss_color=33
fils_discovery_max_interval=20"
	echo "chmod 600 /run/hostapd-u6e/*.conf"
	# A rerun stops the previous instance and waits until its BSSs are gone from
	# the radios, which outlast the process: a radio that still has one refuses
	# the new beacon.
	# Agile Multiband 3.5.2: tell associated clients first that the BSSs
	# terminate imminently (BSS Termination TSF 0, back in about a minute).
	echo 'old=$(cat /run/hostapd-u6e/hostapd.pid 2>/dev/null)
if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
	for i in wlan24 wlan5 wlan6; do
		for sta in $(hostapd_cli -p /run/hostapd -i $i list_sta 2>/dev/null); do
			hostapd_cli -p /run/hostapd -i $i bss_tm_req $sta bss_term=0,1 mbo=0:0 >/dev/null
		done
	done
	sleep 1
fi
if [ -n "$old" ] && kill "$old" 2>/dev/null; then
	for _ in $(seq 20); do kill -0 "$old" 2>/dev/null || break; sleep 0.5; done
fi
for _ in $(seq 20); do
	iw dev | grep -q "^[[:space:]]*ssid " || break
	sleep 0.5
done
# 6 GHz first, so 2.4 and 5 GHz announce it in their RNR from their first
# beacon (hostapd also refreshes them once a later interface starts).
confs=
for i in wlan6 wlan24 wlan5; do
	[ -e /sys/class/net/$i ] && confs="$confs /run/hostapd-u6e/$i.conf" || echo "$i: no such radio"
done
hostapd -B -P /run/hostapd-u6e/hostapd.pid -f /run/hostapd-u6e/hostapd.log $confs || echo "hostapd failed"
sleep 8
# 802.11k: each radio also reports the other two in its neighbor reports,
# marked co-located (BSSID Information bit 16) and, for 2.4/5 GHz, co-located
# with the 6 GHz AP they announce (bit 20) or, for 6 GHz, a member of an ESS
# with 2.4/5 GHz co-located APs (bit 18): byte 8 of the report.
for i in wlan24 wlan5 wlan6; do
	own=$(hostapd_cli -p /run/hostapd -i $i show_neighbor 2>/dev/null | grep " stat$") || continue
	nr=${own#*nr=}; nr=${nr%% *}
	[ $i = wlan6 ] && bits=0x05 || bits=0x11
	b8=$(printf %02x $((0x$(echo "$nr" | cut -c17-18) | bits)))
	nr=$(echo "$nr" | cut -c1-16)$b8$(echo "$nr" | cut -c19-)
	for j in wlan24 wlan5 wlan6; do
		[ $j = $i ] || hostapd_cli -p /run/hostapd -i $j set_neighbor ${own%% *} ssid=$(echo "$own" | sed "s/.*ssid=\([0-9a-f]*\).*/\1/") nr=$nr >/dev/null
	done
done
for i in wlan24 wlan5 wlan6; do
	echo "== $i: $(hostapd_cli -p /run/hostapd -i $i status 2>/dev/null | grep -E "^(state|freq|channel|num_sta\[0\]|ssid\[0\])=" | tr "\n" " ")"
done'
} | T=120 ap_root sh

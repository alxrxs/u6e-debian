#!/bin/bash
# Start the site's SSIDs (WIFI_SSIDS in site.conf) on the radios of the AP
# running our image, each a line name|kind|bands|VLAN:
#   sae      WPA3-Personal with FT
#   ent      WPA3-Enterprise with FT, authenticated over RadSec (RADIUS over
#            TLS, RFC 6614) to the site's RADIUS server
#   psk-mab  WPA2-Personal plus RADIUS MAC authentication, for clients that can
#            do nothing newer
# on the bands named (24 5 6), bridged into br<VLAN>; RADIUS can move an ent
# or psk-mab client into another of WIFI_VLANS. Passphrases, keys and
# certificates come from the site's functions and only ever land in /run on
# the AP.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
FTKEY=$(wifi_ft_key)
# 802.11r: every AP serving an SSID derives the same mobility domain from it.
mdid() { printf %s "$1" | md5sum | cut -c1-4; }
# OCE IP Subnet Identifier: the same for every BSS on a VLAN, on every AP,
# without revealing the subnet.
subnet_id() { printf 'vlan/%s' "$1" | md5sum | cut -c1-12; }

# Per radio.
radio="country_code=$WIFI_COUNTRY
ieee80211d=1
ieee80211h=1
local_pwr_constraint=0
spectrum_mgmt_required=1
ieee80211n=1
ieee80211ax=1
he_su_beamformer=1
he_su_beamformee=1
he_mu_beamformer=1
he_twt_responder=1
he_spr_sr_control=5
he_spr_non_srg_obss_pd_max_offset=10"
# local_pwr_constraint + spectrum_mgmt_required: 802.11h (spectrum management,
# a 0 dB Power Constraint) outside DFS channels too, where hostapd sets it only
# on its own. he_spr_sr_control=5: non-SRG OBSS-PD spatial reuse at
# he_spr_non_srg_obss_pd_max_offset (parameterized SR disallowed).

# Every BSS.
bss="ctrl_interface=/run/hostapd
wmm_enabled=1
uapsd_advertisement_enabled=1
wpa=2
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
wpa_deny_ptk0_rekey=2
bss_load_update_period=50
esp=1
interworking=1
access_network_type=0
internet=1
qos_map_set=8,1,18,3,20,3,22,3,24,4,26,4,28,4,30,4,32,4,34,4,36,4,38,4,40,5,44,6,46,6,0,63,255,255,255,255,255,255,255,255,255,255,255,255,255,255"
# ftm_responder: Fine Timing Measurement responder (802.11-2024 11.21.6), so
# clients can range to the AP for indoor location. esp: Estimated Service
# Parameters, so clients can estimate their throughput. qos_map_set: RFC
# 8325's DSCP to user priority mapping (CS6/CS7 stay best effort), so clients
# mark their uplink the way the network does.
# proxy_arp (802.11v): the bridge answers ARP and IPv6 neighbor solicitations
# for the clients, so broadcast ARP stays off the air; it hairpins client to
# client traffic, so ap_isolate leaves that forwarding to the bridge alone
# (otherwise multicast goes out twice). multicast_to_unicast: group frames
# (mDNS, SSDP, IPv6) reach each client as unicast at its own rate, not the
# basic rate. No wpa_strict_rekey: a group rekey on every departure (dozens an
# hour) has to wake every client, and sleeping phones that miss hostapd's ~3.5 s
# of retries are disconnected.
# wpa_deny_ptk0_rekey=2: never rekey a client's pairwise key in place (the
# driver can't replace it safely: traffic stops until the client is dropped);
# a client asking for one is disconnected and reconnects instead.

# Every BSS with protected management frames (sae, ent): Agile Multiband and
# Optimized Connectivity require them.
pmf() { # <VLAN>
	cat <<PMF
rsn_pairwise=CCMP GCMP-256
group_mgmt_cipher=AES-128-CMAC
ieee80211w=2
ocv=1
ssid_protection=1
ft_over_ds=0
r0kh=ff:ff:ff:ff:ff:ff * $FTKEY
r1kh=00:00:00:00:00:00 00:00:00:00:00:00 $FTKEY
mbo=1
oce=4
oce_ip_subnet_id=$(subnet_id "$1")
enable_dscp_policy_capa=1
PMF
}
# ocv (802.11-2020) and ssid_protection (802.11-2024) bind the channel and SSID
# into the key exchange; ft_over_ds=0 keeps 802.11r roaming over the air only.
# FT's PMK-R0 comes from each SAE or EAP exchange, so a radio pulls a roaming
# client's keys from the one it came from (r0kh/r1kh wildcards with one shared
# key); the R0KH-ID (nas_identifier) is unique per BSS in the mobility domain.
# oce=4: Wi-Fi Optimized Connectivity AP (hostapd answers the probes here).
# enable_dscp_policy_capa: Wi-Fi QoS Management DSCP policies.

# RADIUS over TLS (ent, psk-mab): hostapd speaks it itself, mutually
# authenticated with the site's RadSec client certificate; hostapd takes only
# addresses, so the server's name is resolved here.
radius=
for e in "${WIFI_SSIDS[@]}"; do
	case $e in *"|ent|"* | *"|psk-mab|"*) radius=y ;; esac
done
if [ -n "$radius" ]; then
	RADSEC=$(getent ahostsv4 "$WIFI_RADSEC_SERVER" | awk 'NR == 1 {print $1}')
	[ -n "$RADSEC" ] || { echo "$WIFI_RADSEC_SERVER: no IPv4 address" >&2; exit 1; }
	RADSEC_PASS=$(radsec_key_pass)
	radius="own_ip_addr=$AP"
	for s in auth acct; do
		radius="$radius
${s}_server_addr=$RADSEC
${s}_server_port=2083
${s}_server_type=TLS
${s}_server_shared_secret=radsec
${s}_server_ca_cert=/run/hostapd-u6e/radsec/ca.pem
${s}_server_client_cert=/run/hostapd-u6e/radsec/client.pem
${s}_server_private_key=/run/hostapd-u6e/radsec/client.key
${s}_server_private_key_passwd=$RADSEC_PASS"
	done
fi

# One SSID's own lines, by kind.
kind() { # <name> <kind> <VLAN> <iface>
	echo "ssid=$1"
	echo "bridge=br$3"
	case $2 in
	sae)
		# WPA3-Personal on every band: 6 GHz admits nothing else, and clients
		# (iOS) only treat the 6 GHz BSS as the same network when 2.4/5 GHz
		# offer the same security. SAE-EXT-KEY (AKMs 24/25, WPA3 3.5) with
		# GCMP-256 and SAE groups 20/21 next to SAE/CCMP: clients that support
		# it use it, the rest keep SAE; group traffic stays CCMP-128 and
		# BIP-CMAC-128, which every client supports. Hash-to-element only
		# (sae_pwe=1): 6 GHz admits no hunting-and-pecking.
		cat <<SAE
sae_password=$(wifi_psk "$1")
mobility_domain=$(mdid "$1")
transition_disable=0x01
wpa_key_mgmt=SAE SAE-EXT-KEY FT-SAE FT-SAE-EXT-KEY
sae_groups=19 20 21
sae_pwe=1
SAE
		pmf "$3" ;;
	ent)
		# WPA3-Enterprise Only Mode (WPA3 3.5 3.2): 802.1X with SHA-256 plus
		# FT, never SHA-1. No periodic EAP reauthentication: each one ends in
		# an in-place pairwise rekey.
		cat <<ENT
mobility_domain=$(mdid "$1")
transition_disable=0x04
wpa_key_mgmt=WPA-EAP-SHA256 FT-EAP
ieee8021x=1
eap_reauth_period=0
radius_request_cui=1
dynamic_vlan=1
vlan_file=/run/hostapd-u6e/$4.vlan
$radius
ENT
		pmf "$3" ;;
	psk-mab)
		# WPA2-Personal without PMF, plus RADIUS MAC authentication (which
		# also assigns the VLAN): for clients that can do nothing newer, so no
		# Agile Multiband, Optimized Connectivity or FT either.
		cat <<MAB
wpa_passphrase=$(wifi_psk "$1")
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ieee80211w=0
macaddr_acl=2
dynamic_vlan=1
vlan_file=/run/hostapd-u6e/$4.vlan
$radius
MAB
		;;
	*) echo "unknown SSID kind: $2" >&2; exit 1 ;;
	esac
}

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

# Each radio's own lines and its BSS extras (DTIM as on the UniFi controller).
# On 2.4 GHz the WPA3 BSSs are OFDM only, so their beacons and management
# frames go at 6 Mbit/s rather than 1 (Wi-Fi Optimized Connectivity wants at
# least 5.5); psk-mab keeps the 802.11b rates for the cheapest IoT radios.
# hostapd takes rates per BSS. rnr: 2.4 and 5 GHz
# beacons announce the 6 GHz BSSs (Reduced Neighbor Report), which is how most
# clients find 6 GHz at all; hostapd only reports a 6 GHz BSS it runs in the
# same process. FILS Discovery (802.11ai) every 20 ms between beacons speeds
# up 6 GHz scans. member_of_colocated_6ghz_ess: every 6 GHz BSS of the site's
# ESSs has its SSID on 2.4 or 5 GHz of the same AP, so STAs that have its RNR
# entry or neighbor report can skip scanning 6 GHz for it.
read -r COLOR_24 COLOR_5 COLOR_6 <<<"$WIFI_COLORS"
radio_lines() { # <band>
	case $1 in
	24) printf '%s\nhe_bss_color=%s\n' "$(ht "$WIFI_24" "$HT_CAPS")" "$COLOR_24" ;;
	5) printf '%s\nvht_capab=%s\nhe_bss_color=%s\n' "$(ht "$WIFI_5" "${HT_CAPS}[MAX-AMSDU-7935]")" "$VHT_CAPS_5" "$COLOR_5" ;;
	6) printf '%s\nhe_bss_color=%s\n' "$WIFI_6" "$COLOR_6" ;;
	esac
}
bss_extra() { # <band> <kind>
	case $1 in
	24)
		printf 'rnr=1\ndtim_period=1\n'
		[ "$2" = psk-mab ] ||
			printf 'supported_rates=60 90 120 180 240 360 480 540\nbasic_rates=60 120 240\n' ;;
	5) printf 'rnr=1\ndtim_period=3\n' ;;
	6) printf 'fils_discovery_max_interval=20\ndtim_period=3\nmember_of_colocated_6ghz_ess=1\n' ;;
	esac
}

# A radio's config: its first SSID on the radio's own interface, every further
# one a BSS on a locally administered address derived from the radio's (set on
# the AP). Prints the AP-side commands; collects each SSID's interfaces in
# group[] for the neighbor reports.
declare -a group
radio_conf() { # <band>
	local n=0 e name kind bands vlan iface
	echo "cat > /run/hostapd-u6e/wlan$1.conf <<'EOF'"
	for i in "${!WIFI_SSIDS[@]}"; do
		e=${WIFI_SSIDS[$i]}
		IFS='|' read -r name kind bands vlan <<<"$e"
		case " $bands " in *" $1 "*) ;; *) continue ;; esac
		[ "$1:$kind" != 6:psk-mab ] || { echo "$name: 6 GHz admits only WPA3" >&2; exit 1; }
		if [ $n = 0 ]; then
			iface=wlan$1
			printf 'interface=%s\n%s\n%s\n' $iface "$radio" "$(radio_lines $1)"
		else
			iface=wlan$1-$n
			printf 'bss=%s\nbssid=@LA%s@\n' $iface $n
		fi
		printf '%s\n%s\n%s\nnas_identifier=%s-%s\n' "$bss" "$(kind "$name" $kind $vlan $iface)" \
			"$(bss_extra $1 $kind)" "$AP" $iface
		group[$i]="${group[$i]:-} $iface"
		n=$((n + 1))
	done
	echo "EOF"
}

{
	echo "mkdir -p /run/hostapd-u6e && chmod 700 /run/hostapd-u6e && rm -f /run/hostapd-u6e/*.conf /run/hostapd-u6e/*.vlan"
	if [ -n "$radius" ]; then
		echo "mkdir -p /run/hostapd-u6e/radsec"
		for f in ca:radsec_ca client:radsec_cert client.key:radsec_key; do
			n=${f%%:*}; [ "$n" = client.key ] || n=$n.pem
			echo "cat > /run/hostapd-u6e/radsec/$n <<'EOF'"
			"${f#*:}"
			echo "EOF"
		done
		echo "chmod 600 /run/hostapd-u6e/radsec/*"
	fi
	# The radios regulate themselves (firmware default: US); move them to the
	# site's country before hostapd reads its channel list. ath11k only passes a
	# country to a radio's firmware once that radio is started, i.e. has an
	# interface up.
	echo "for i in wlan24 wlan5 wlan6; do ip link set \$i up; done
iw reg set $WIFI_COUNTRY
for _ in \$(seq 20); do [ \"\$(iw reg get | grep -c '^country $WIFI_COUNTRY')\" -ge 3 ] && break; sleep 0.5; done
iw reg get | grep -E '^(phy|country)' | paste - - | sed 's/^/reg: /'"
	for b in 24 5 6; do radio_conf $b; done
	# The BSSIDs: the radio's address with the locally administered bit set and
	# the BSS's number in its fifth octet. The VLAN files: a RADIUS-assigned
	# client's interface goes into that VLAN's bridge.
	echo "WIFI_VLANS='$WIFI_VLANS'"
	echo 'for b in 24 5 6; do
	c=/run/hostapd-u6e/wlan$b.conf
	set -- $(sed "s/:/ /g" /sys/class/net/wlan$b/address)
	for n in $(sed -n "s/^bssid=@LA\([0-9]*\)@$/\1/p" $c); do
		sed -i "s/^bssid=@LA$n@$/bssid=$(printf %02x:%s:%s:%s:%02x:%s $((0x$1 | 2)) $2 $3 $4 $((0x$5 ^ n)) $6)/" $c
	done
	for v in $(sed -n "s#^vlan_file=/run/hostapd-u6e/\(.*\)\.vlan\$#\1#p" $c); do
		for id in $WIFI_VLANS; do echo "$id $v.$id br$id"; done > /run/hostapd-u6e/$v.vlan
	done
done
chmod 600 /run/hostapd-u6e/*.conf'
	# A rerun stops the previous instance and waits until its BSSs are gone from
	# the radios, which outlast the process: a radio that still has one refuses
	# the new beacon.
	# Agile Multiband 3.5.2: tell associated clients first that the BSSs
	# terminate imminently (BSS Termination TSF 0, back in about a minute).
	echo 'old=$(cat /run/hostapd-u6e/hostapd.pid 2>/dev/null)
if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
	for i in $(ls /run/hostapd); do
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
hostapd -B -s -P /run/hostapd-u6e/hostapd.pid $confs || echo "hostapd failed"
sleep 8'
	# The site's transmit power per radio (the regulatory limit still applies).
	read -r tx24 tx5 tx6 <<<"$WIFI_TXPOWER"
	echo "iw dev wlan24 set txpower fixed $((tx24 * 100)); iw dev wlan5 set txpower fixed $((tx5 * 100)); iw dev wlan6 set txpower fixed $((tx6 * 100))"
	# 802.11k: each of an SSID's BSSs also reports its others in its neighbor
	# reports, marked co-located (BSSID Information bit 16) and, for 2.4/5 GHz,
	# co-located with the 6 GHz AP they announce (bit 20): byte 8 of the report.
	# hostapd sets bit 18 of a 6 GHz BSS itself (member_of_colocated_6ghz_ess).
	for g in "${group[@]}"; do
		echo "ifs='${g# }'"
		echo 'for i in $ifs; do
	own=$(hostapd_cli -p /run/hostapd -i $i show_neighbor 2>/dev/null | grep " stat$") || continue
	nr=${own#*nr=}; nr=${nr%% *}
	case $i in wlan6*) bits=0x01 ;; *) bits=0x11 ;; esac
	b8=$(printf %02x $((0x$(echo "$nr" | cut -c17-18) | bits)))
	nr=$(echo "$nr" | cut -c1-16)$b8$(echo "$nr" | cut -c19-)
	for j in $ifs; do
		[ $j = $i ] || hostapd_cli -p /run/hostapd -i $j set_neighbor ${own%% *} ssid=$(echo "$own" | sed "s/.*ssid=\([0-9a-f]*\).*/\1/") nr=$nr >/dev/null
	done
done'
	done
	echo 'for i in wlan24 wlan5 wlan6; do
	echo "== $i: $(hostapd_cli -p /run/hostapd -i $i status 2>/dev/null | grep -E "^(state|freq|channel|ssid\[[0-9]\]|num_sta\[[0-9]\])=" | tr "\n" " ")"
done'
} | T=120 ap_root sh

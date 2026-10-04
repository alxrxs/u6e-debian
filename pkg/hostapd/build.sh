#!/bin/bash
# Build hostapd from a pinned upstream main commit (newer than the 2.12
# release: AP-side Wi-Fi QoS Management, the 2026-5 RADIUS fix) as a Debian
# package, from Debian's newest packaging (wpa 2.11-2, experimental) with
# every hostapd feature built in: out/hostapd_<ver>_arm64.deb, which
# mkrootfs.sh installs and holds. Run as root; needs qemu-user binfmt.
set -euo pipefail
cd "$(dirname "$0")"
REV=5b156e272a0266ca6be0f394192bad42b0ff176c  # hostap main, 2026-10-01
UP=2.13~git20261001 DEBVER=2.11-2 VER=2:2.13~git20261001-0+u6e6
[ ! -e work ] || { echo "work exists; remove it first" >&2; exit 1; }
mkdir work; mkdir -p out
git clone -q https://w1.fi/hostap.git work/src
git -C work/src archive --prefix=wpa-$UP/ "$REV" | xz > work/wpa_$UP.orig.tar.xz
tar -xJf work/wpa_$UP.orig.tar.xz -C work
curl -fsSL -o work/debian.tar.xz https://deb.debian.org/debian/pool/main/w/wpa/wpa_$DEBVER.debian.tar.xz
tar -xJf work/debian.tar.xz -C work/wpa-$UP
D=work/wpa-$UP/debian
# Fixed upstream since 2.11 (the CVE, extra-IEs and sae_pk_gen ones differently), or wpa_supplicant-only
# unit changes this package does not ship.
sed -i '/^Bump-DEFAULT_BSS_MAX_COUNT-to-1000.patch$/d; /^CVE-2024-5290-lib_engine_trusted_path.patch$/d;
	/^upstream-fixes\/0001-nl80211-add-extra-ies-only-if-allowed-by-driver.patch$/d;
	/^0014-sae_pk_gen-needs-random_get_bytes-wpa_key_mgmt_txt-w.patch$/d;
	/^systemd-add-reload-support.patch$/d; /^wpa_service_netdev.patch$/d' $D/patches/series
# Ours, for upstream (each patch's message says what and why): no_pri_sec_switch, RNR 6 GHz PSD, BSS TM Query candidates,
# Link Measurement responder, DSCP policy fixes, the Mobility Domain bit, the
# ESP element, the Neighbor Report ANQP-element, FILS Request Parameters
# parsing, and OCE AP: probe handling, Transmit Power and IP Subnet attributes,
# co-located RNR and AP Channel Report, and a single MBO-OCE element on RSSI
# rejection; the BTM cellular preference only for cellular STAs; and a zero
# Medium Time for downlink TSPECs.
for p in no-pri-sec-switch-option rnr-6ghz-psd \
	btm-query-candidates rrm-link-measurement-responder dscp-policy-fixes \
	nr-mobility-domain esp-element anqp-neighbor-report fils-req-params-length \
	oce-ap-probe-handling oce-tx-power-ip-subnet \
	oce-colocated-rnr-ap-channel-report oce-rssi-reject-single-ie \
	mbo-cell-pref-optional wmm-downlink-medium-time; do
	cp $p.patch $D/patches/
	echo $p.patch >> $D/patches/series
done
cat hostapd.config >> $D/config/hostapd/linux
# nodoc installs no examples, which this rule's glob assumes.
sed -i 's#^\tsed -e .s="includes.h"#\t-sed -e \x27s="includes.h"#' $D/rules
sed -i '/^CONFIG_TESTING_OPTIONS=y$/d' $D/config/hostapd/linux
{ printf 'wpa (%s) experimental; urgency=medium\n\n' "$VER"
  printf '  * hostapd from upstream main %s with every hostapd feature built in\n' "${REV:0:9}"
  printf '    (hostapd.config); no testing options.\n\n'
  printf ' -- Andrei-Alexandru Bleortu <me@andrei-z.com>  %s\n\n' "$(date -R)"
  cat $D/changelog; } > work/changelog
mv work/changelog $D/changelog
# Build-Depends and its continuation lines, without the GUI/doc-only ones;
# first of any alternatives.
deps=$(awk '/^Build-Depends:/{f=1; sub(/^Build-Depends:/, ""); print; next} f && /^[ \t]/{print; next} {f=0}' $D/control |
	tr ',' '\n' | grep -v '<!pkg.wpa.nogui>\|<!nodoc>' | sed 's/|.*//; s/[[(<].*//; s/ //g' |
	grep -vE '^$|^dh-sequence-' | sed 's/^debhelper-compat$/debhelper/' | paste -sd,)
mmdebstrap --variant=buildd --architectures=arm64 --include="$deps,dh-sequence-installsysusers,libsqlite3-dev" \
	trixie work/chroot http://deb.debian.org/debian
cp -a work/wpa-$UP work/wpa_$UP.orig.tar.xz work/chroot/
chroot work/chroot sh -c "cd /wpa-$UP && DEB_BUILD_PROFILES='pkg.wpa.nogui noudeb nodoc' \
	DEB_BUILD_OPTIONS='nocheck nodoc' dpkg-buildpackage -b -uc -us"
cp work/chroot/hostapd_${VER#2:}_arm64.deb out/
rm -rf work

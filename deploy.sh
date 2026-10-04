#!/bin/bash
# Build the current tree and boot it on the APs. Run as root, after the kernel
# and nss/build.sh:
#   ./deploy.sh [<ap>...]      (default: every AP in U6E_APS)
# The hostapd package is built when its version has no .deb yet, and the rootfs
# rebuilt when it does not carry that version (remove rootfs/ to force one).
# Then each AP in turn gets its image (prep-rootfs.sh nss, kept under images/),
# boots it (boot/stage.sh) and must bring its radios up by itself. Build logs
# go to log/.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
. ./site.conf
L=$PWD/log
mkdir -p "$L"
fail() { echo "$*" >&2; exit 1; }
ver=$(sed -n 's/.* VER=2:\([^ ]*\).*/\1/p' pkg/hostapd/build.sh)
[ -n "$ver" ] || fail "no VER= in pkg/hostapd/build.sh"
if [ ! -f "pkg/hostapd/out/hostapd_${ver}_arm64.deb" ]; then
	(cd pkg/hostapd && ./build.sh) > "$L/hostapd.log" 2>&1 || fail "hostapd $ver: build failed, see $L/hostapd.log"
	echo "hostapd $ver built"
fi
if [ "$(dpkg-query --admindir=rootfs/var/lib/dpkg -W -f '${Version}' hostapd 2>/dev/null)" != "2:$ver" ]; then
	rm -rf "$PWD/rootfs"
	./mkrootfs.sh arm64 > "$L/mkrootfs.log" 2>&1 || fail "rootfs: build failed, see $L/mkrootfs.log"
	echo "rootfs built with hostapd $ver"
fi
if [ $# = 0 ]; then
	read -ra aps <<<"$U6E_APS"
	set -- "${aps[@]}"
fi
for ap in "$@"; do
	export U6E_AP=$ap
	./prep-rootfs.sh nss > "$L/prep-$ap.log" 2>&1 || fail "$ap: image build failed, see $L/prep-$ap.log"
	grep "^kept as" "$L/prep-$ap.log"
	boot/stage.sh || fail "$ap: did not boot the image"
	up=
	for _ in $(seq 30); do
		up=$(cd boot && . ./lib.sh && T=15 ap_root -n 'systemctl is-active -q u6e-wifi &&
			for i in wlan24 wlan5 wlan6; do hostapd_cli -p /run/hostapd -i $i status | grep -x state=ENABLED; done | wc -l' 2>/dev/null)
		[ "$up" = 3 ] && break
		sleep 10
	done
	[ "$up" = 3 ] || fail "$ap: Wi-Fi did not come up"
	echo "$ap: Wi-Fi up on all three radios"
done

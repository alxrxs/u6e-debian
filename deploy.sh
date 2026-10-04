#!/bin/bash
# Build whatever the checked-out commits need and boot it on the APs. Run as
# root:
#   ./deploy.sh [<ap>...]      (default: every AP in U6E_APS)
# First the source trees (trees.sh: the kernel and backports releases with our
# patch series). Then each step runs only when its inputs changed since it
# last ran (stamps/ records them): the board files ($BLOBS), the kernel
# (kernel/ and config-u6e.sh), the NSS drivers and wireless stack (backports/,
# nss/ and the kernel), the hostapd and iproute2 packages (their versions) and
# the rootfs (those packages and mkrootfs.sh). Then each AP in turn gets its
# image (prep-rootfs.sh, kept under images/), boots it (boot/stage.sh) and must
# bring its radios up by itself. Sources and trees are built as the checkout's
# owner, the packages and images as root. Logs go to log/.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
. ./site.conf
L=$PWD/log
mkdir -p "$L"
fail() { echo "$*" >&2; exit 1; }
as_owner() { sudo -u "$(stat -c %U .)" "$@"; }
head_of() { git -c safe.directory='*' -C "$1" rev-parse "${2:-HEAD}"; }
# step <name> <inputs> <command>...: run the command unless stamps/<name>
# already records these inputs.
mkdir -p stamps
step() {
	local name=$1 stamp=stamps/$1 inputs=$2
	shift 2
	[ "$(cat "$stamp" 2>/dev/null)" = "$inputs" ] && return
	"$@" > "$L/$name.log" 2>&1 || fail "$name: failed, see $L/$name.log"
	echo "$inputs" > "$stamp"
	echo "$name: built"
}
pkg_version() { sed -n "s/.*\b$2=\([^ ]*\).*/\1/p" "pkg/$1/build.sh" | head -1; }

as_owner ./trees.sh > "$L/trees.log" 2>&1 || fail "trees: failed, see $L/trees.log"
step board-files "$(head_of "$BLOBS")" as_owner fw/mk-board2.sh
kernel=$(head_of linux-7.2.8)/$(head_of . HEAD:config-u6e.sh)
step kernel "$kernel" as_owner sh -c './config-u6e.sh &&
	make -C linux-7.2.8 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j"$(nproc)" Image modules qcom/ipq5018-ubnt-u6-enterprise.dtb'
step nss "$kernel/$(head_of backports-7.2)/$(head_of . HEAD:nss)" as_owner nss/build.sh

hostapd=$(sed -n 's/.* VER=2:\([^ ]*\).*/\1/p' pkg/hostapd/build.sh)
iproute2=$(pkg_version iproute2-nss VER)-$(pkg_version iproute2-nss DEB)+nss1
[ -n "$hostapd" ] && [ "$iproute2" != -+nss1 ] || fail "no package versions in pkg/*/build.sh"
[ -f "pkg/hostapd/out/hostapd_${hostapd}_arm64.deb" ] ||
	step hostapd "$hostapd" pkg/hostapd/build.sh
[ -f "pkg/iproute2-nss/out/iproute2_${iproute2}_arm64.deb" ] ||
	step iproute2 "$iproute2" sh -c 'rm -rf pkg/iproute2-nss/work && pkg/iproute2-nss/build.sh'
step rootfs "$hostapd/$iproute2/$(head_of . HEAD:mkrootfs.sh)" sh -c 'rm -rf "$PWD/rootfs" && ./mkrootfs.sh'

if [ $# = 0 ]; then
	read -ra aps <<<"$U6E_APS"
	set -- "${aps[@]}"
fi
for ap in "$@"; do
	export U6E_AP=$ap
	./prep-rootfs.sh > "$L/prep-$ap.log" 2>&1 || fail "$ap: image build failed, see $L/prep-$ap.log"
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

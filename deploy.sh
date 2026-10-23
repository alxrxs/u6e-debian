#!/bin/bash
# Build whatever the checked-out commits need and boot it on the APs. Run as
# root:
#   ./deploy.sh [<ap>...]      (default: every AP in U6E_APS)
#   FORCE=1 ./deploy.sh ...    (boot a new image even where nothing changed)
#   BOOT=0 ./deploy.sh ...     (build everything, each AP's image included,
#                               but boot nothing: a later run boots it)
# First the source trees (trees.sh: the kernel and backports releases with our
# patch series). Then each step runs only when its inputs changed since it
# last ran (stamps/ records them): the board files ($BLOBS), the kernel
# (kernel/ and config-u6e.sh), the NSS drivers and wireless stack (backports/,
# nss/ and the kernel), the hostapd and iproute2 packages (their versions) and
# the rootfs (those packages and mkrootfs.sh); the packages and the rootfs on
# the native builder if it answers (arm64 below), and u6e-agent
# (pkg/u6e-agent). Then each AP whose running
# image was built from other inputs (stamps/ap-<ap>) gets a new one (prep-rootfs.sh,
# kept under images/), boots it (boot/stage.sh) and must bring its radios up by
# itself. Sources and trees are built as the checkout's
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
# arm64 <result> <command> <input>...: run a build that needs arm64 userland
# and leaves <result>. When NATIVE_BUILD ("<ssh login> <OrbStack machine>", an
# Apple silicon Mac) answers, it runs in that machine (OrbStack started and the
# machine created first if need be) with the inputs sent and the result
# fetched; else here, under qemu-user, several times slower.
arm64() {
	local result=$1 cmd=$2 mac vm job
	shift 2
	read -r mac vm <<<"${NATIVE_BUILD:-}"
	if [ -z "$mac" ] || ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$mac" true 2>/dev/null; then
		echo "arm64: no native builder, building under emulation"
		sh -c "$cmd"
		return
	fi
	echo "arm64: building on $mac in $vm"
	local orb='PATH=$PATH:$HOME/.orbstack/bin:/usr/local/bin:/opt/homebrew/bin orb'
	local deps='command -v mmdebstrap > /dev/null || { apt-get update -qq &&
		DEBIAN_FRONTEND=noninteractive apt-get install -qq -y git curl xz-utils ca-certificates dpkg-dev mmdebstrap > /dev/null; }'
	ssh -o BatchMode=yes "$mac" "$orb status | grep -qx Running || open -ga OrbStack
		for _ in \$(seq 60); do $orb status | grep -qx Running && break; sleep 2; done
		$orb list -q | grep -qx $vm || $orb create -a arm64 debian:trixie $vm
		$orb start $vm && $orb -m $vm -u root sh -c $(printf %q "$deps")" || return
	job="rm -rf /root/u6e && mkdir /root/u6e && cd /root/u6e && tar -xf - &&
		{ $cmd; } >&2 && tar --xattrs --numeric-owner -cf - $result"
	rm -rf -- "./$result"
	tar -cf - --exclude='*/work' "$@" |
		ssh -o BatchMode=yes "$mac" "$orb -m $vm -u root sh -c $(printf %q "$job")" |
		tar --xattrs --xattrs-include='*' --numeric-owner -xpf -
	local rc="${PIPESTATUS[*]}"
	[ "$rc" = "0 0 0" ] && [ -e "$result" ]
}

as_owner ./trees.sh > "$L/trees.log" 2>&1 || fail "trees: failed, see $L/trees.log"
step board-files "$(head_of "$BLOBS")" as_owner fw/mk-board2.sh
kernel=$(head_of linux-7.2.8)/$(head_of . HEAD:config-u6e.sh)
step kernel "$kernel" as_owner sh -c './config-u6e.sh &&
	make -C linux-7.2.8 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j"$(nproc)" Image modules qcom/ipq5018-ubnt-u6-enterprise.dtb'
step nss "$kernel/$(head_of backports-7.2)/$(head_of . HEAD:nss)" as_owner nss/build.sh

hostapd=$(sed -n 's/.* VER=2:\([^ ]*\).*/\1/p' pkg/hostapd/build.sh)
iproute2=$(pkg_version iproute2-nss VER)-$(pkg_version iproute2-nss DEB)+nss1
netlogd=$(pkg_version netlogd VER)-$(pkg_version netlogd DEB)+u6e1
[ -n "$hostapd" ] && [ "$iproute2" != -+nss1 ] && [ "$netlogd" != -+u6e1 ] || fail "no package versions in pkg/*/build.sh"
deb=pkg/hostapd/out/hostapd_${hostapd}_arm64.deb
[ -f "$deb" ] || step hostapd "$hostapd" arm64 "$deb" 'rm -rf pkg/hostapd/work && pkg/hostapd/build.sh' pkg/hostapd
deb=pkg/iproute2-nss/out/iproute2_${iproute2}_arm64.deb
[ -f "$deb" ] || step iproute2 "$iproute2" arm64 "$deb" 'rm -rf pkg/iproute2-nss/work && pkg/iproute2-nss/build.sh' pkg/iproute2-nss
deb=pkg/netlogd/out/systemd-netlogd_${netlogd}_arm64.deb
[ -f "$deb" ] || step netlogd "$netlogd" arm64 "$deb" 'rm -rf pkg/netlogd/work && pkg/netlogd/build.sh' pkg/netlogd
step rootfs "$hostapd/$iproute2/$netlogd/$(head_of . HEAD:mkrootfs.sh)" arm64 rootfs 'rm -rf rootfs && ./mkrootfs.sh' \
	mkrootfs.sh pkg/hostapd/out pkg/iproute2-nss/out pkg/netlogd/out
# u6e-agent: a static arm64 binary, cross-built here (rustup's
# aarch64-unknown-linux-musl target).
[ -x pkg/u6e-agent/target/aarch64-unknown-linux-musl/release/u6e-agent ] || rm -f stamps/agent
step agent "$(head_of . HEAD:pkg/u6e-agent)" sh -c \
	'cd pkg/u6e-agent && PATH=$PATH:$HOME/.cargo/bin cargo build --release --locked'

if [ $# = 0 ]; then
	read -ra aps <<<"$U6E_APS"
	set -- "${aps[@]}"
fi
# Everything an AP's image is built from: this tree, the blobs, the site and
# the two source trees.
image=$(head_of .)/$(head_of "$BLOBS")/$(sha256sum < site.conf | cut -c1-16)/$(head_of linux-7.2.8)/$(head_of backports-7.2)
for ap in "$@"; do
	export U6E_AP=$ap
	if [ "${FORCE:-0}" != 1 ] && [ "$(cat "stamps/ap-$ap" 2>/dev/null)" = "$image" ]; then
		echo "$ap: already runs this image"
		continue
	fi
	./prep-rootfs.sh > "$L/prep-$ap.log" 2>&1 || fail "$ap: image build failed, see $L/prep-$ap.log"
	grep "^kept as" "$L/prep-$ap.log"
	if [ "${BOOT:-1}" = 0 ]; then
		echo "$ap: image built, not booted (BOOT=0)"
		continue
	fi
	boot/stage.sh || fail "$ap: did not boot the image"
	up=
	for _ in $(seq 30); do
		up=$(cd boot && . ./lib.sh && T=15 ap_root -n 'systemctl is-active -q u6e-wifi &&
			for i in wlan24 wlan5 wlan6; do hostapd_cli -p /run/hostapd -i $i status | grep -x state=ENABLED; done | wc -l' 2>/dev/null)
		[ "$up" = 3 ] && break
		sleep 10
	done
	[ "$up" = 3 ] || fail "$ap: Wi-Fi did not come up"
	echo "$image" > "stamps/ap-$ap"
	echo "$ap: Wi-Fi up on all three radios"
done

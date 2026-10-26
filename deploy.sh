#!/bin/bash
# Build whatever the checked-out commits need and boot it on the APs. Run as
# root:
#   ./deploy.sh [<ap>...]      (default: every AP in U6E_APS)
#   FORCE=1 ./deploy.sh ...    (boot even an AP that already runs this build)
#   BOOT=0 ./deploy.sh ...     (build everything, each AP's image included,
#                               but boot nothing: a later run boots it)
# First the source trees (trees.sh: the kernel and backports releases with our
# patch series). Then each step runs only when its inputs changed since it
# last ran (stamps/ records them): the board files ($BLOBS), the kernel
# (kernel/ and config-u6e.sh), the NSS drivers and wireless stack (backports/,
# nss/ and the kernel), the hostapd and iproute2 packages (their versions) and
# the rootfs (those packages and mkrootfs.sh); the packages and the rootfs on
# the native builder if it answers (arm64 below), and u6e-agent
# (pkg/u6e-agent, only by the toolchain rust-toolchain.toml and toolchain.env
# pin). Then each AP whose running image was built from other
# inputs (stamps/ap-<ap>) gets its image of the current inputs (ap-image.sh:
# the one an earlier run kept under images/, else a new one from
# prep-rootfs.sh), boots it (boot/stage.sh) and must bring its radios up by
# itself; FORCE=1 boots it even on an AP that already runs it. Sources and
# trees are built as the checkout's owner, the packages and images as root.
# Logs go to log/.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
. ./site.conf
. ./ap-image.sh
. ./toolchain.env
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
# u6e-agent and u6e-spectral: static arm64 binaries from the cargo workspace,
# cross-built here (cargo-zigbuild: zig is the C toolchain for musl crates such
# as aws-lc-sys), only by the pinned toolchain: any other builds another binary.
export PATH=$PATH:$HOME/.cargo/bin
rust=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
[ "$(rustc --version 2>/dev/null | cut -d' ' -f2)" = "$rust" ] ||
	fail "rustc $rust needed (rust-toolchain.toml, through rustup), found: $(rustc --version 2>&1)"
[ "$(zig version 2>/dev/null)" = "$ZIG_VERSION" ] ||
	fail "zig $ZIG_VERSION needed (toolchain.env), found: $(zig version 2>&1)"
[ "$(cargo-zigbuild --version 2>/dev/null)" = "cargo-zigbuild $CARGO_ZIGBUILD_VERSION" ] ||
	fail "cargo-zigbuild $CARGO_ZIGBUILD_VERSION needed (toolchain.env), found: $(cargo-zigbuild --version 2>&1)"
for b in u6e-agent u6e-spectral; do
	[ -x target/aarch64-unknown-linux-musl/release/$b ] || rm -f stamps/agent
done
step agent "$(head_of . HEAD:Cargo.toml)/$(head_of . HEAD:Cargo.lock)/$(head_of . HEAD:.cargo)/$(head_of . HEAD:rust-toolchain.toml)/$(head_of . HEAD:toolchain.env)/$(head_of . HEAD:pkg/u6e-agent)/$(head_of . HEAD:pkg/u6e-spectral)/$(head_of . HEAD:pkg/u6e-proto)" \
	cargo zigbuild --release --locked --target aarch64-unknown-linux-musl -p u6e-agent -p u6e-spectral

if [ $# = 0 ]; then
	read -ra aps <<<"$U6E_APS"
	set -- "${aps[@]}"
fi
# Everything an AP's image is built from: what this repository puts into it
# (ap-image.sh's image_tree), the blobs, the site and the two source trees.
tree=$(image_tree) || fail "image_tree: cannot read this checkout's image inputs"
image=$tree/$(head_of "$BLOBS")/$(sha256sum < site.conf | cut -c1-16)/$(head_of linux-7.2.8)/$(head_of backports-7.2)
# The deploy runner holds the same lock on images/ for each rollout, its gate
# and its way back included (u6e-deploy --stage-helper), so a rollout and
# this loop never have two APs down at once: while one runs, this refuses.
mkdir -p images
exec {lock}<images
flock -n "$lock" ||
	fail "images/ is locked: a rollout of the deploy runner, or another deploy, is under way; run again once it is over"
for ap in "$@"; do
	export U6E_AP=$ap
	ap_image "$ap" "$image" || continue
	if [ "${BOOT:-1}" = 0 ]; then
		echo "$ap: not booted (BOOT=0)"
		continue
	fi
	boot/stage.sh "$IMAGE" || fail "$ap: did not boot $IMAGE"
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
	# The runner rolls an AP back to the image staged on it last.
	if declare -F runner_staged > /dev/null; then
		runner_staged "$ap" "${IMAGE##*/}" ||
			fail "$ap: booted, but the deploy runner was not told it runs ${IMAGE##*/}"
	fi
done

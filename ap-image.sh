# shellcheck shell=bash
# Sourced by deploy.sh (with its fail and log directory L): the key of what
# this repository puts into an image, and which kept image an access point
# boots.

# The paths an image is built from: the scripts that build it and everything
# they build into it (prep-rootfs.sh reads boot/wifi-up.sh, u6e-caldata and
# the outputs of the rest). The README, test/, the controller and the AP
# binaries' tests and examples go into no image, so a commit touching only
# those reboots no access point. A new input of the image goes into this list.
IMAGE_PATHS=(deploy.sh ap-image.sh prep-rootfs.sh mkrootfs.sh config-u6e.sh u6e-caldata
	boot/wifi-up.sh boot/lib.sh kernel backports nss fw shim pkg/hostapd pkg/iproute2-nss pkg/netlogd
	Cargo.toml .cargo rust-toolchain.toml toolchain.env
	pkg/u6e-agent/Cargo.toml pkg/u6e-agent/src pkg/u6e-spectral/Cargo.toml pkg/u6e-spectral/src
	pkg/u6e-proto/Cargo.toml pkg/u6e-proto/src)

# image_tree [<rev>]: the key of IMAGE_PATHS and of agent_lock at <rev>
# (default HEAD).
image_tree() {
	local rev=${1:-HEAD} lock
	lock=$(agent_lock "$rev") || return
	{ git -c safe.directory='*' ls-tree -r "$rev" -- "${IMAGE_PATHS[@]}"; echo "$lock"; } |
		sha256sum | cut -c1-16
}

# agent_lock <rev>: the Cargo.lock entries of the AP's binaries, u6e-agent and
# u6e-spectral, and of every package they depend on, at <rev>; a dependency of
# the controller alone is left out.
agent_lock() {
	git -c safe.directory='*' show "$1:Cargo.lock" | python3 -c '
import sys, tomllib
pkgs = tomllib.loads(sys.stdin.read())["package"]
def find(dep):  # "name", "name version" or "name version (source)"
    name, *rest = dep.split(" ")
    return next(p for p in pkgs if p["name"] == name and (not rest or p["version"] == rest[0]))
todo, seen = [find("u6e-agent"), find("u6e-spectral")], {}
while todo:
    p = todo.pop()
    if (p["name"], p["version"]) not in seen:
        seen[p["name"], p["version"]] = p
        todo += [find(d) for d in p.get("dependencies", [])]
for k in sorted(seen):
    print(seen[k])
'
}

# ap_image <ap> <key>: set IMAGE to the images/ directory to boot on <ap> for
# the image inputs <key>, or return 1 when <ap> already runs <key>
# (stamps/ap-<ap>, written by deploy.sh after a boot) unless FORCE=1. The
# image built last for <ap> (stamps/built-<ap>: "<key> <dir>") is reused while
# it has this key and is still kept, so an image built ahead (BOOT=0) is the
# one a later run boots; else prep-rootfs.sh builds one.
ap_image() {
	local ap=$1 key=$2 built
	IMAGE=
	if [ "${FORCE:-0}" != 1 ] && [ "$(cat "stamps/ap-$ap" 2>/dev/null)" = "$key" ]; then
		echo "$ap: already runs this image"
		return 1
	fi
	built=$(cat "stamps/built-$ap" 2>/dev/null)
	if [ "${built%% *}" = "$key" ] && [ -f "${built#* }/MANIFEST" ]; then
		IMAGE=${built#* }
		echo "$ap: $IMAGE was built for these inputs"
		return
	fi
	U6E_AP=$ap ./prep-rootfs.sh > "$L/prep-$ap.log" 2>&1 || fail "$ap: image build failed, see $L/prep-$ap.log"
	IMAGE=$(sed -n 's/^kept as //p' "$L/prep-$ap.log")
	[ -f "$IMAGE/MANIFEST" ] || fail "$ap: prep-rootfs.sh kept no image, see $L/prep-$ap.log"
	echo "$key $IMAGE" > "stamps/built-$ap"
	echo "$ap: built $IMAGE"
}

# boot_ap <ap> <key>: boot <ap>'s image of the inputs <key> (ap_image) on it,
# unless it runs it already or BOOT=0, and wait for its radios; then
# stamps/ap-<ap> records it. The deploy runner (site.conf's runner_staged)
# is told what was staged as soon as it is, before anything can stop the
# run: until it is told, no stamp is written, so the next run stages the
# image again and tells it then.
boot_ap() {
	local ap=$1 key=$2 up=
	ap_image "$ap" "$key" || return 0
	if [ "${BOOT:-1}" = 0 ]; then
		echo "$ap: not booted (BOOT=0)"
		return 0
	fi
	boot/stage.sh "$IMAGE" || fail "$ap: did not boot $IMAGE"
	echo "${IMAGE##*/}" > "stamps/running-$ap"
	if declare -F runner_staged > /dev/null; then
		runner_staged "$ap" "${IMAGE##*/}" ||
			fail "$ap: booted $IMAGE, but the deploy runner was not told; run again"
	fi
	for _ in $(seq 30); do
		up=$(cd boot && . ./lib.sh && T=15 ap_root -n 'systemctl is-active -q u6e-wifi &&
			for i in wlan24 wlan5 wlan6; do hostapd_cli -p /run/hostapd -i $i status | grep -x state=ENABLED; done | wc -l' 2>/dev/null)
		[ "$up" = 3 ] && break
		sleep 10
	done
	[ "$up" = 3 ] || fail "$ap: Wi-Fi did not come up"
	echo "$key" > "stamps/ap-$ap"
	echo "$ap: Wi-Fi up on all three radios"
}

# prune_images [<tree>]: remove the kept images nothing needs from <tree>'s
# images/ (default this checkout's), by this checkout's prune-images.py, so
# another tree's is pruned by the same rule without running its code. Kept
# are each AP's running image (stamps/running-<ap>, which boot_ap writes as
# it stages one), its image of the current inputs (stamps/built-<ap>), the
# images the deploy runner needs (site.conf's runner_images: what it staged
# on each AP, both of a rollout under way), and the newest KEEP_IMAGES
# (default 3) of each AP. Nothing is pruned while an AP's running image is
# not known, or the runner does not say which it needs.
prune_images() {
	local tree=${1:-.} here keep=() aps ap built ids id
	here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
	read -ra aps <<< "$U6E_APS"
	for ap in "${aps[@]}"; do
		built=$(head -c 1024 "$tree/stamps/built-$ap" 2> /dev/null) && keep+=(--keep "${built##*/}")
		if [ -s "$tree/stamps/running-$ap" ]; then
			keep+=(--keep "$(head -c 1024 "$tree/stamps/running-$ap")")
		elif [ -e "$tree/stamps/ap-$ap" ] && [ "$(head -c 1024 "$tree/stamps/ap-$ap")" != "${built%% *}" ]; then
			echo "images: what $ap runs is not known (no stamps/running-$ap in $tree); none pruned"
			return 0
		fi
	done
	if declare -F runner_images > /dev/null; then
		ids=$(runner_images) || {
			echo "images: the deploy runner did not say which images it needs; none pruned"
			return 0
		}
		for id in $ids; do
			keep+=(--keep "$id")
		done
	fi
	python3 -I "$here/prune-images.py" "$tree/images" --newest "${KEEP_IMAGES:-3}" "${keep[@]}"
}

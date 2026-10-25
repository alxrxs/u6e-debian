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

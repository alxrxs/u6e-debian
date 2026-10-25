# shellcheck shell=bash
# Sourced by deploy.sh (with its fail and log directory L): which kept image
# an access point boots.
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

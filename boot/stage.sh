#!/bin/bash
# Boot an image directory (default out-nss/, or one kept under images/) on the
# AP that U6E_AP names: from our image, disarm the next boot and reboot into
# stock; stage the image there with go8.sh; reboot stock and wait until our
# image answers.
#   U6E_AP=<ap> boot/stage.sh [<image dir>]
set -uo pipefail
B=$(cd "$(dirname "$0")" && pwd)
. "$B/lib.sh"
dir=$(cd "${1:-$U6E/out-nss}" && pwd) || exit 1
wait_for() { # <state> <seconds>
	local t0=$SECONDS
	until [ "$("$B/apstate.sh")" = "$1" ]; do
		[ $((SECONDS - t0)) -lt "$2" ] || { echo "$AP_HOSTNAME: not $1 after $2 s" >&2; return 1; }
		sleep 10
	done
	echo "$AP_HOSTNAME: $1 after $((SECONDS - t0)) s"
}
# The ssh session dies with the reboot, so its status says nothing.
if [ "$("$B/apstate.sh")" = debian ]; then
	T=20 ap_root -n '/usr/local/sbin/u6e-arm disarm && systemctl reboot'
	sleep 30
	wait_for stock 400 || exit 1
fi
(cd "$dir" && "$B/go8.sh" shim.bin u6e.dtb u6e.initrd Image) || exit 1
T=20 ap_stock -n reboot
sleep 30
wait_for debian 600

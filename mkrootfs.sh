#!/bin/bash
# Bootstrap the Debian trixie root filesystem the images are built from:
#   mkrootfs.sh arm64 -> rootfs/        (the arm64 and nss images)
#   mkrootfs.sh armhf -> rootfs-armhf/  (the arm image)
# Run as root; a foreign architecture needs qemu-user binfmt. prep-rootfs.sh
# then adds the kernel, the firmware and the AP's configuration. The arm64
# rootfs takes iproute2 from pkg/iproute2-nss (tc with the NSS qdiscs) and
# hostapd from pkg/hostapd (2.12, every feature), both held so apt cannot swap
# them for Debian's; radsecproxy stays off until it is configured.
# shellcheck disable=SC2016 # each mmdebstrap hook gets the chroot as its own $1
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-}" in
	arm64) dir=rootfs ;;
	armhf) dir=rootfs-armhf ;;
	*) echo "usage: $0 arm64|armhf" >&2; exit 2 ;;
esac
[ ! -e "$dir" ] || { echo "$dir exists; remove it first" >&2; exit 1; }
localdeb=()
if [ "$1" = arm64 ]; then
	# out/ keeps every build; take the newest.
	tc=$(printf '%s\n' pkg/iproute2-nss/out/iproute2_*+nss*_arm64.deb | sort -V | tail -1)
	ap=$(printf '%s\n' pkg/hostapd/out/hostapd_*+u6e*_arm64.deb | sort -V | tail -1)
	localdeb=(--include="$PWD/$tc,$PWD/$ap" --customize-hook='chroot "$1" apt-mark hold iproute2 hostapd')
fi
mmdebstrap --variant=minbase --architectures="$1" --components=main,non-free-firmware "${localdeb[@]}" \
	--include=systemd-sysv,udev,kmod,procps,iproute2,iputils-ping,less,vim-tiny,tzdata,ca-certificates \
	--include=openssh-server,systemd-resolved,ethtool,pciutils,mmc-utils,mtd-utils,nftables,tcpdump,iperf3 \
	--include=iw,hostapd,wireless-regdb,firmware-atheros,qrtr-tools,libubootenv-tool,radsecproxy,fastfetch,bluez \
	--customize-hook='chroot "$1" systemctl disable radsecproxy' \
	trixie "$dir" http://deb.debian.org/debian

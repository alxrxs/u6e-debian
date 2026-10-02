#!/bin/bash
# Bootstrap the Debian trixie root filesystem the images are built from:
#   mkrootfs.sh arm64 -> rootfs/        (the arm64 and nss images)
#   mkrootfs.sh armhf -> rootfs-armhf/  (the arm image)
# Run as root; a foreign architecture needs qemu-user binfmt. prep-rootfs.sh
# then adds the kernel, the firmware and the AP's configuration.
set -euo pipefail
cd "$(dirname "$0")"
case "${1:-}" in
	arm64) dir=rootfs ;;
	armhf) dir=rootfs-armhf ;;
	*) echo "usage: $0 arm64|armhf" >&2; exit 2 ;;
esac
[ ! -e "$dir" ] || { echo "$dir exists; remove it first" >&2; exit 1; }
mmdebstrap --variant=minbase --architectures="$1" --components=main,non-free-firmware \
	--include=systemd-sysv,udev,kmod,procps,iproute2,iputils-ping,less,vim-tiny,tzdata,ca-certificates \
	--include=openssh-server,systemd-resolved,ethtool,pciutils,mmc-utils,mtd-utils,nftables,tcpdump,iperf3 \
	--include=iw,hostapd,wireless-regdb,firmware-atheros,qrtr-tools \
	trixie "$dir" http://deb.debian.org/debian

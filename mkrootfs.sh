#!/bin/bash
# Bootstrap the Debian trixie root filesystem the images are built from:
#   mkrootfs.sh arm64 -> rootfs/        (the arm64 and nss images)
#   mkrootfs.sh armhf -> rootfs-armhf/  (the arm image)
# Run as root; a foreign architecture needs qemu-user binfmt. prep-rootfs.sh
# then adds the kernel, the firmware and the AP's configuration. The arm64
# rootfs takes iproute2 from pkg/iproute2-nss (tc with the NSS qdiscs) and
# hostapd from pkg/hostapd (pinned upstream main, every feature), both held so apt cannot swap
# them for Debian's; radsecproxy stays off until it is configured, and so does
# hostapd's own unit, since boot/wifi-up.sh runs hostapd.
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
	# apt inside the chroot cannot see host paths: copy the packages in
	localdeb=(--customize-hook="mkdir -p \"\$1/tmp/u6e-debs\"" \
		--customize-hook="copy-in $PWD/$tc $PWD/$ap /tmp/u6e-debs" \
		--customize-hook='chroot "$1" sh -c "apt-get install -y /tmp/u6e-debs/*.deb && rm -r /tmp/u6e-debs"' \
		--customize-hook='chroot "$1" apt-mark hold iproute2 hostapd')
fi
mmdebstrap --variant=minbase --architectures="$1" --components=main,non-free-firmware "${localdeb[@]}" \
	--include=systemd-sysv,udev,kmod,procps,iproute2,iputils-ping,less,vim-tiny,tzdata,ca-certificates \
	--include=openssh-server,systemd-resolved,systemd-timesyncd,ethtool,pciutils,mmc-utils,mtd-utils,nftables,tcpdump,iperf3 \
	--include=iw,hostapd,wireless-regdb,firmware-atheros,qrtr-tools,libubootenv-tool,radsecproxy,fastfetch,bluez \
	--include=systemd-netlogd \
	--customize-hook='chroot "$1" systemctl disable radsecproxy hostapd' \
	trixie "$dir" http://deb.debian.org/debian

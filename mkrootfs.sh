#!/bin/bash
# Bootstrap the Debian trixie (arm64) root filesystem the images are built
# from: mkrootfs.sh -> rootfs/. Run as root; needs qemu-user binfmt.
# prep-rootfs.sh then adds the kernel, the firmware and the AP's configuration.
# iproute2 comes from pkg/iproute2-nss (tc with the NSS qdiscs) and hostapd from
# pkg/hostapd (pinned upstream main, every feature), both held so apt cannot
# swap them for Debian's; hostapd's own unit stays off, since u6e-wifi.service
# (prep-rootfs.sh) runs hostapd.
# shellcheck disable=SC2016 # each mmdebstrap hook gets the chroot as its own $1
set -euo pipefail
cd "$(dirname "$0")"
[ ! -e rootfs ] || { echo "rootfs exists; remove it first" >&2; exit 1; }
# out/ keeps every build; take the newest.
tc=$(printf '%s\n' pkg/iproute2-nss/out/iproute2_*+nss*_arm64.deb | sort -V | tail -1)
ap=$(printf '%s\n' pkg/hostapd/out/hostapd_*+u6e*_arm64.deb | sort -V | tail -1)
# apt inside the chroot cannot see host paths: copy the packages in.
mmdebstrap --variant=minbase --architectures=arm64 --components=main,non-free-firmware \
	--customize-hook="mkdir -p \"\$1/tmp/u6e-debs\"" \
	--customize-hook="copy-in $PWD/$tc $PWD/$ap /tmp/u6e-debs" \
	--customize-hook='chroot "$1" sh -c "apt-get install -y /tmp/u6e-debs/*.deb && rm -r /tmp/u6e-debs"' \
	--customize-hook='chroot "$1" apt-mark hold iproute2 hostapd' \
	--include=systemd-sysv,udev,kmod,procps,iproute2,iputils-ping,less,vim-tiny,tzdata,ca-certificates \
	--include=openssh-server,systemd-resolved,systemd-timesyncd,ethtool,pciutils,mmc-utils,mtd-utils,nftables,tcpdump,iperf3 \
	--include=iw,hostapd,wireless-regdb,firmware-atheros,qrtr-tools,libubootenv-tool,fastfetch,bluez \
	--include=systemd-netlogd \
	--customize-hook='chroot "$1" systemctl disable hostapd' \
	trixie rootfs http://deb.debian.org/debian

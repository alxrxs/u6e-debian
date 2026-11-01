#!/bin/bash
# Build Debian's iproute2 with the Qualcomm NSS qdiscs in tc (OpenWrt's
# 400-add-nss-qdisc.patch): out/iproute2_<ver>+nss1_arm64.deb, which
# mkrootfs.sh installs and holds. Run as root, on arm64 or with qemu-user binfmt.
set -euo pipefail
cd "$(dirname "$0")"
VER=6.15.0 DEB=1
[ ! -e work ] || { echo "work exists; remove it first" >&2; exit 1; }
mkdir work; mkdir -p out
../fetch-debian.sh work 20250527T022950Z main/i/iproute2 \
	2558690474d6cdda5e2c4022b520935623ddd41fbf8e936315e3f4314f6f21dd=iproute2_$VER-$DEB.dsc \
	8041854a882583ad5263466736c9c8c68c74b1a35754ab770d23343f947528fb=iproute2_$VER.orig.tar.xz \
	780375193dffeb85f310a918b806f2f4e480f76b815a1f0f1eac5d0488ea1a8f=iproute2_$VER-$DEB.debian.tar.xz
dpkg-source -x work/iproute2_$VER-$DEB.dsc work/iproute2-$VER
cp nss-qdisc.patch work/iproute2-$VER/debian/patches/
echo nss-qdisc.patch >> work/iproute2-$VER/debian/patches/series
{ printf 'iproute2 (%s-%s+nss1) trixie; urgency=medium\n\n' $VER $DEB
  printf '  * tc: add the Qualcomm NSS qdiscs, from OpenWrt'"'"'s 400-add-nss-qdisc.patch.\n\n'
  printf ' -- Andrei-Alexandru Bleortu <me@andrei-z.com>  %s\n\n' "$(date -R)"
  cat work/iproute2-$VER/debian/changelog; } > work/changelog
mv work/changelog work/iproute2-$VER/debian/changelog
deps=$(sed -n '/^Build-Depends:/,/^$/p' work/iproute2-$VER/debian/control | sed '1s/^Build-Depends://' |
	tr ',' '\n' | sed 's/[[(<].*//; s/ //g' | grep -vE '^$|^dh-sequence-' | sed 's/^debhelper-compat$/debhelper/' | paste -sd,)
mmdebstrap --variant=buildd --architectures=arm64 --include="$deps" trixie work/chroot http://deb.debian.org/debian
cp -a work/iproute2-$VER work/iproute2_$VER.orig.tar.xz work/chroot/
chroot work/chroot sh -c "cd /iproute2-$VER && DEB_BUILD_OPTIONS='nocheck nodoc' dpkg-buildpackage -b -uc -us"
cp work/chroot/iproute2_$VER-$DEB+nss1_arm64.deb out/
rm -rf work

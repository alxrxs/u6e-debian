#!/bin/bash
# Build Debian's iproute2 with the Qualcomm NSS qdiscs in tc (OpenWrt's
# 400-add-nss-qdisc.patch): out/iproute2_<ver>+nss1_arm64.deb, which
# mkrootfs.sh installs and holds. Run as root; needs qemu-user binfmt.
set -euo pipefail
cd "$(dirname "$0")"
VER=6.15.0 DEB=1
[ ! -e work ] || { echo "work exists; remove it first" >&2; exit 1; }
mkdir work out
base=https://deb.debian.org/debian/pool/main/i/iproute2
for f in iproute2_$VER-$DEB.dsc iproute2_$VER.orig.tar.xz iproute2_$VER-$DEB.debian.tar.xz; do
	curl -fsSL -o "work/$f" "$base/$f"
done
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

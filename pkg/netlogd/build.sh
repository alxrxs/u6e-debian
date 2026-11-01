#!/bin/bash
# Build Debian's systemd-netlogd with the journal-rotation fix (each patch's
# header says what and why): out/systemd-netlogd_<ver>+u6e1_arm64.deb, which
# mkrootfs.sh installs and holds. Run as root, on arm64 or with qemu-user binfmt.
set -euo pipefail
cd "$(dirname "$0")"
VER=1.4.4 DEB=1
[ ! -e work ] || { echo "work exists; remove it first" >&2; exit 1; }
mkdir work; mkdir -p out
../fetch-debian.sh work 20250216T205656Z main/s/systemd-netlogd \
	51fbb0eaeaaa68ef6b80b01049200e8d93c7765a378e1d920a186bf14f44acf4=systemd-netlogd_$VER-$DEB.dsc \
	041144dbc3196d657fba494a288dee7afcef8719a0c5c2573086f77cabff986a=systemd-netlogd_$VER.orig.tar.gz \
	dee0e6cb2793bcfaa2c46c6eda03f8d805e37c7bb8bde08f95005ba80b33c6b4=systemd-netlogd_$VER-$DEB.debian.tar.xz
dpkg-source -x work/systemd-netlogd_$VER-$DEB.dsc work/systemd-netlogd-$VER
cp journal-rotation-cursor.patch work/systemd-netlogd-$VER/debian/patches/
echo journal-rotation-cursor.patch >> work/systemd-netlogd-$VER/debian/patches/series
{ printf 'systemd-netlogd (%s-%s+u6e1) trixie; urgency=medium\n\n' $VER $DEB
  printf '  * Keep the last cursor when the current entry was rotated away.\n\n'
  printf ' -- Andrei-Alexandru Bleortu <me@andrei-z.com>  %s\n\n' "$(date -R)"
  cat work/systemd-netlogd-$VER/debian/changelog; } > work/changelog
mv work/changelog work/systemd-netlogd-$VER/debian/changelog
# Build-Depends and its continuation lines.
deps=$(awk '/^Build-Depends:/{f=1; sub(/^Build-Depends:/, ""); print; next} f && /^[ \t]/{print; next} {f=0}' \
	work/systemd-netlogd-$VER/debian/control | tr ',' '\n' |
	sed 's/[[(<].*//; s/ //g' | grep -vE '^$|^dh-sequence-' | sed 's/^debhelper-compat$/debhelper/' | paste -sd,)
mmdebstrap --variant=buildd --architectures=arm64 --include="$deps" trixie work/chroot http://deb.debian.org/debian
cp -a work/systemd-netlogd-$VER work/systemd-netlogd_$VER.orig.tar.gz work/chroot/
chroot work/chroot sh -c "cd /systemd-netlogd-$VER && DEB_BUILD_OPTIONS='nocheck nodoc' dpkg-buildpackage -b -uc -us"
cp work/chroot/systemd-netlogd_$VER-$DEB+u6e1_arm64.deb out/
rm -rf work

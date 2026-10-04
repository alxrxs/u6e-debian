#!/bin/bash
# Build Qualcomm's NSS host drivers, then the 7.2 wireless stack (backports:
# cfg80211, mac80211, ath11k with NSS Wi-Fi offload), out of tree against
# linux-7.2.8:
#   nss/build.sh   (everything, in dependency order)
# Each source is cloned on first use, reset to its pinned commit (sources.txt)
# and gets its patch set (patches/<package>: kuncy7/nss-packages' series for
# nss-drv, ECM, the clients and MCS, qosmio's fixes for the client managers and
# nss-drv paths kuncy7 does not build, and our own); headers a later package
# includes are staged in stage/, modules land in out/<kernel release>/. The wireless stack is the
# patched ../backports-7.2 tree that trees.sh builds. Ethernet is mainline
# dwmac-ipq5018; qca-dwmac-nss hands its GMACs to the NSS firmware.
# Flags mirror the OpenWrt package recipes with every engine the IPQ5018
# firmware ships switched on.
set -euo pipefail
N=$(cd "$(dirname "$0")" && pwd)
K=$N/../linux-7.2.8
BP=$N/../backports-7.2
KV=$(cat "$K/include/config/kernel.release")
STAGE=$N/stage OUT=$N/out/$KV
X=aarch64-linux-gnu-
NSSFW=nss-firmware-2025.05.01
NSSFW_SHA256=10a4b1e69470db150915cb063525436494b8ae4eebb8b50ea6ad894082d7abb0
NSSFW_URL=https://github.com/qosmio/qca-sdk-nss-fw/releases/download/v2025.05.01/$NSSFW.tar.zst
NSSFW_IPQ5018=QCA_Networking_2022.SPF_12.2/ED1/IPQ5018.ATH.12.2/BIN-NSS.FW.12.2-156-MP.R.tar.bz2
# The firmware line every package lays the NSS messages out for (headers are shared).
NSSFW_DEF=-DNSS_FIRMWARE_VERSION_12_2
KM=(make -C "$K" ARCH=arm64 CROSS_COMPILE="$X" KERNELRELEASE="$KV" -j"$(nproc)")
# Package flags go in CFLAGS_MODULE: kbuild appends it after a module's own
# ccflags (where EXTRA_CFLAGS went before 7.x dropped it), so these -Wno-*
# outrank the vendor Makefiles' -Wall -Werror.
W="-Wno-missing-prototypes -Wno-missing-declarations"

prepare() { # <package>: pinned source + its patches
	local s=$N/src/$1 url rev sub repo
	case $1 in backports|firmware) return ;; esac
	read -r url rev sub < <(awk -v p="$1" '$1==p {print $2, $3, $4}' "$N/sources.txt")
	if [ -n "$sub" ]; then
		# A package that lives in a subdirectory of a larger repo (a blobless
		# bare clone in src/): only that subdirectory, at the pinned commit.
		repo=$N/src/$(basename "$url")
		[ -d "$repo" ] || git clone -q --bare --filter=blob:none "$url" "$repo"
		rm -rf "$s"; mkdir -p "$s"
		git -C "$repo" archive "$rev" "$sub" |
			tar -x -C "$s" --strip-components="$(awk -F/ '{print NF}' <<< "$sub")"
	else
		[ -d "$s/.git" ] || git clone -q "$url" "$s"
		git -C "$s" -c advice.detachedHead=false checkout -qf "$rev"
		git -C "$s" clean -qfdx
	fi
	if [ -d "$N/patches/$1" ]; then
		for p in "$N"/patches/"$1"/*.patch; do patch -d "$s" -p1 -s -f --no-backup-if-mismatch < "$p"; done
	fi
}
SYMVERS=() # Module.symvers of the packages built so far, for KBUILD_EXTRA_SYMBOLS
symvers() { echo "${SYMVERS[*]}"; }
collect() { # <package>: its modules into out/, its exports into the symbol chain
	local f
	install -d "$OUT"
	while IFS= read -r f; do
		"${X}strip" --strip-debug -o "$OUT/$(basename "$f")" "$f"
	done < <(find "$N/src/$1" -name '*.ko')
	while IFS= read -r f; do SYMVERS+=("$f"); done < <(find "$N/src/$1" -name Module.symvers)
}
stage() { # <dir> <file>...: headers for later packages
	local d=$STAGE/$1; shift
	install -d "$d"; cp -r "$@" "$d/"
}

build() {
	local s=$N/src/$1
	prepare "$1"
	case $1 in
	qca-dwmac-nss)
		"${KM[@]}" M="$s" modules
		stage qca-dwmac-nss "$s"/exports/* ;;
	qca-nss-drv)
		# No PPE on this SoC, hence no qca-ssdk and no PPE virtual ports.
		ln -sf arch/nss_ipq50xx_64.h "$s"/exports/nss_arch.h
		"${KM[@]}" M="$s" SoC=ipq50xx_64 KBUILD_EXTRA_SYMBOLS="$(symvers)" \
			CFLAGS_MODULE="-I$STAGE/qca-dwmac-nss $W -Wno-empty-body -Wno-unused-variable -DNSS_MEM_PROFILE_MEDIUM $NSSFW_DEF" \
			NSS_DRV_PPE_VP_ENABLE=n NSS_DRV_WIFI_LEGACY_ENABLE=n modules
		stage qca-nss-drv "$s"/exports/*
		rm -f "$STAGE"/qca-nss-drv/nss_ipsecmgr.h ;;
	qca-nss-crypto)
		"${KM[@]}" M="$s" SoC=ipq50xx NSS_CRYPTO_DIR=v2.0 KBUILD_EXTRA_SYMBOLS="$(symvers)" \
			CFLAGS_MODULE="-DCONFIG_NSS_DEBUG_LEVEL=4 $NSSFW_DEF -I$STAGE/qca-nss-crypto -I$STAGE/qca-nss-drv -I$s/v2.0/include -I$s/v2.0/src" modules
		stage qca-nss-crypto "$s"/v2.0/include/* ;;
	qca-nss-cfi)
		# The crypto engine behind the kernel crypto API (AEAD/skcipher/ahash),
		# which ipsecmgr and in-kernel IPsec offload through.
		"${KM[@]}" M="$s" SoC=ipq50xx KBUILD_EXTRA_SYMBOLS="$(symvers)" cryptoapi=y NSS_CRYPTOAPI_ABLK=n \
			NSS_CRYPTOAPI_SKCIPHER=y CFI_CRYPTOAPI_DIR=cryptoapi/v2.0 CFI_IPSEC_DIR=ipsec/v2.0 \
			CFLAGS_MODULE="-DCONFIG_NSS_DEBUG_LEVEL=4 $NSSFW_DEF -I$STAGE/qca-nss-crypto -I$STAGE/qca-nss-drv" modules
		stage qca-nss-cfi "$s"/cryptoapi/exports/* ;;
	nat46)
		# The MAP-T/464XLAT translator whose flows the NSS map-t engine offloads.
		"${KM[@]}" M="$s/nat46/modules" KBUILD_EXTRA_SYMBOLS="$(symvers)" \
			CFLAGS_MODULE="-DNAT46_VERSION=\\\"$(awk '$1=="nat46" {print $3}' "$N/sources.txt")\\\"" modules
		stage nat46 "$s"/nat46/modules/*.h ;;
	qca-mcs)
		"${KM[@]}" M="$s" KBUILDPATH="$K" MDIR="$s" KERNELPATH= KERNELRELEASE=1 CONFIG_SUPPORT_MLD=y \
			CFLAGS_MODULE=-Wno-implicit-fallthrough KBUILD_EXTRA_SYMBOLS="$(symvers)" modules
		stage qca-mcs "$s"/mc_api.h "$s"/mc_ecm.h ;;
	# ECM and the clients cover every engine the IPQ5018 firmware declares in its
	# DT node (qcom,*-enabled); QVPN/OpenVPN, TLS, DTLS, CAPWAP and MSCS exist only
	# in the IPQ807x/60xx firmware. bridge-mgr programs the PPE switch and portifmgr
	# the IPQ806x GMAC; this SoC has neither (ECM accelerates bridged flows itself).
	qca-nss-ecm)
		"${KM[@]}" M="$s" SoC=ipq50xx KBUILD_EXTRA_SYMBOLS="$(symvers)" \
			CFLAGS_MODULE="-I$STAGE/qca-nss-drv -I$STAGE/qca-mcs -I$STAGE/nat46 $NSSFW_DEF" \
			ECM_NON_PORTED_SUPPORT_ENABLE=y ECM_FRONT_END_NSS_ENABLE=y ECM_IPV6_ENABLE=y ECM_MULTICAST_ENABLE=y \
			ECM_INTERFACE_VLAN_ENABLE=y ECM_BRIDGE_VLAN_FILTERING_ENABLE=y ECM_INTERFACE_VXLAN_ENABLE=y \
			ECM_INTERFACE_MACVLAN_ENABLE=y ECM_INTERFACE_BOND_ENABLE=y ECM_INTERFACE_PPPOE_ENABLE=y \
			ECM_INTERFACE_PPP_ENABLE=y ECM_INTERFACE_PPTP_ENABLE=y ECM_INTERFACE_L2TPV2_ENABLE=y \
			ECM_INTERFACE_GRE_TAP_ENABLE=y ECM_INTERFACE_GRE_TUN_ENABLE=y ECM_INTERFACE_SIT_ENABLE=y \
			ECM_INTERFACE_TUNIPIP6_ENABLE=y ECM_INTERFACE_IPSEC_ENABLE=y ECM_INTERFACE_MAP_T_ENABLE=y \
			ECM_CLASSIFIER_MARK_ENABLE=y ECM_CLASSIFIER_DSCP_ENABLE=y ECM_CLASSIFIER_DSCP_IGS=y \
			ECM_CLASSIFIER_PCC_ENABLE=y ECM_DB_ADVANCED_STATS_ENABLE=y modules
		stage qca-nss-ecm "$s"/exports/* ;;
	qca-nss-clients)
		"${KM[@]}" M="$s" SoC=ipq50xx_64 KBUILD_EXTRA_SYMBOLS="$(symvers)" \
			qdisc=y igs=y netlink=y vxlanmgr=y match=y mirror=y vlan-mgr=y lag-mgr=y \
			pppoe=y pptp=y l2tpv2=y gre=y tunipip6=y tun6rd=m pvxlanmgr=y eogremgr=y clmapmgr=y \
			ipsecmgr=y ipsecmgr-xfrm=y map-t=y wifi-meshmgr=y IPSECMGR_DIR=v2.0 \
			CFLAGS_MODULE="-I$STAGE/qca-nss-drv -I$STAGE/qca-nss-crypto -I$STAGE/qca-nss-cfi -I$STAGE/nat46 -I$STAGE/qca-nss-ecm -I$s/exports -DNSS_VXLAN_ENABLED $NSSFW_DEF $W -Wno-empty-body -include $s/compat.h" modules
		stage qca-nss-clients "$s"/netlink/include/* "$s"/exports/* ;;
	backports)
		# The 7.2 wireless subsystem; the kernel's own cfg80211/mac80211 are off.
		rm -rf "$s"; mkdir -p "$s"
		git -C "$BP" archive HEAD | tar -x -C "$s"
		# Headers the kernel provides itself (OpenWrt's Build/Prepare drops the same set).
		rm -rf "$s"/include/linux/ssb "$s"/include/linux/bcma "$s"/include/net/bluetooth \
			"$s"/include/linux/{cordic,crc8,eeprom_93cx6,wl12xx,mhi}.h "$s"/include/net/ieee80211.h \
			"$s"/backport-include/linux/bcm47xx_nvram.h
		cp "$N/backports.config" "$s/.config"
		local bp=(make -C "$s" ARCH=arm64 CROSS_COMPILE="$X" KLIB_BUILD="$K" KLIB="/lib/modules/$KV" MODPROBE=true
			CFLAGS_MODULE="-I$s/include -I$STAGE/qca-nss-drv -I$STAGE/qca-nss-clients $NSSFW_DEF"
			KBUILD_EXTRA_SYMBOLS="$(symvers)")
		"${bp[@]}" allnoconfig
		"${bp[@]}" -j"$(nproc)" modules ;;
	firmware)
		# NSS core firmware: Qualcomm's QSDK 12.2 IPQ5018 build (May 2025, the newest
		# for this SoC; 12.5 ignores the host's TX checksum flags), as republished by
		# qosmio/qca-sdk-nss-fw (Qualcomm's own repo stops at 12.0).
		[ -f "$N/dl/$NSSFW.tar.zst" ] || { mkdir -p "$N/dl"; curl -fsSL -o "$N/dl/$NSSFW.tar.zst" "$NSSFW_URL"; }
		echo "$NSSFW_SHA256  $N/dl/$NSSFW.tar.zst" | sha256sum -c --quiet
		rm -rf "$s"; mkdir -p "$s" "$OUT/firmware"
		zstd -dc "$N/dl/$NSSFW.tar.zst" | tar -x -C "$s" --strip-components=1 "$NSSFW/$NSSFW_IPQ5018"
		tar -xJf "$s/$NSSFW_IPQ5018" -O --wildcards '*/retail_router0.bin' > "$OUT/firmware/qca-nss0-retail.bin"
		echo "built firmware $(strings "$OUT/firmware/qca-nss0-retail.bin" | grep -m1 -o 'NSS\.FW\.[0-9A-Za-z.-]*')"
		return ;;
	*) echo "unknown package $1" >&2; exit 2 ;;
	esac
	collect "$1"
	echo "built $1"
}

rm -rf "$STAGE" "$OUT"
for p in qca-dwmac-nss qca-nss-drv qca-nss-crypto qca-nss-cfi nat46 qca-mcs qca-nss-ecm qca-nss-clients backports firmware; do build "$p"; done
ls "$OUT"

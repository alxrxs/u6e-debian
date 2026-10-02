#!/bin/bash
# Configure the U6-Enterprise kernel: config-u6e.sh arm|arm64|nss
#   arm   -> ../linux-arm      (armv7 LPAE zImage, booted directly by bootz)
#   arm64 -> ../linux-7.2.8    (arm64 Image, entered through shim/ via the TZ switch)
#   nss   -> ../linux-7.2.8    (arm64 + Qualcomm NSS offload hooks; Wi-Fi comes from
#                               the out-of-tree backports build, so not from here)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
case "${1:-}" in
	arm)   tree=linux-arm   defconfig=multi_v7_defconfig cross=arm-linux-gnueabihf-
	       platforms=$(grep -hE "^(menu)?config (ARCH|SOC)_[A-Z0-9_]+$" "$here/$tree"/arch/arm/mach-*/Kconfig | awk '{print $2}' | sort -u) ;;
	arm64|nss)
	       tree=linux-7.2.8 defconfig=defconfig cross=aarch64-linux-gnu-
	       platforms=$(grep -hE "^(menu)?config ARCH_[A-Z0-9_]+$" "$here/$tree"/arch/arm64/Kconfig.platforms | awk '{print $2}' | sort -u) ;;
	*) echo "usage: $0 arm|arm64|nss" >&2; exit 2 ;;
esac
cd "$here/$tree"
export ARCH=${1/nss/arm64} CROSS_COMPILE=$cross
make -s $defconfig
./scripts/config \
	-e ARCH_QCOM -e PINCTRL_IPQ5018 -e IPQ_GCC_5018 -e IPQ_CMN_PLL \
	-e QCOM_APCS_IPC -e IPQ_APSS_PLL -e IPQ_APSS_6018 \
	-e STMMAC_ETH -e STMMAC_PLATFORM -e DWMAC_IPQ5018 -e PCS_QCA_UNIPHY -e FWNODE_PCS \
	-e MDIO_IPQ4019 -e AT803X_PHY -e QCA808X_PHY -e PHY_QCOM_UNIPHY_PCIE_USB3_28LP \
	-e PCI -e PCI_MSI -e PCIE_QCOM \
	-e EXPERT -e CFG80211_CERTIFICATION_ONUS -e ATH_REG_DYNAMIC_USER_REG_HINTS \
	-m ATH11K -e ATH11K_DEBUG -e DYNAMIC_DEBUG -m ATH11K_PCI -e REMOTEPROC -m ATH11K_AHB -m QCOM_Q6V5_MPD -m QCOM_Q6V5_WCSS_SEC -m QRTR -m QRTR_MHI \
	-e MMC_SDHCI_PLTFM -e MMC_SDHCI_MSM -e SPI_QUP -e MTD_SPI_NOR \
	-e SERIAL_MSM -e SERIAL_MSM_CONSOLE -e NVMEM_QCOM_QFPROM -e QCOM_TSENS -e QCOM_SCM \
	-e CRYPTO_DEV_QCOM_RNG -e WATCHDOG -e QCOM_WDT -e INPUT_KEYBOARD -e KEYBOARD_GPIO \
	-m VXLAN -m MACSEC -m WIREGUARD -m TUN -m BRIDGE -m VLAN_8021Q \
	-e NETFILTER -e NETFILTER_ADVANCED -m NF_TABLES -e NF_TABLES_INET -e NF_TABLES_NETDEV \
	-m NFT_CT -m NFT_NAT -m NFT_MASQ -m NFT_REJECT -m NFT_FIB_INET -m NFT_FIB_IPV4 \
	-m NFT_FIB_IPV6 -m NFT_LOG -m NFT_LIMIT -m NF_NAT -m NF_CONNTRACK \
	-e BLK_DEV_INITRD -e RD_ZSTD -e DEVTMPFS -e DEVTMPFS_MOUNT -e FHANDLE -e CGROUPS \
	-e AUTOFS_FS -e TMPFS_POSIX_ACL -e EXT4_FS --set-str INITRAMFS_SOURCE "" \
	-e PSTORE -e PSTORE_RAM -e PSTORE_CONSOLE -e PSTORE_PMSG \
	-e SOFTLOCKUP_DETECTOR --set-val BOOTPARAM_SOFTLOCKUP_PANIC 1 -e HARDLOCKUP_DETECTOR -e BOOTPARAM_HARDLOCKUP_PANIC \
	-e FTRACE -d FUNCTION_TRACER -m NETCONSOLE -e NETCONSOLE_DYNAMIC \
	-d LOCALVERSION_AUTO --set-str LOCALVERSION "-u6e" \
	--set-str CMDLINE "console=ttyMSM0,115200n8 panic=10 coherent_pool=2M" -e CMDLINE_FORCE
# Only build for this SoC: every other platform goes, and its drivers fall
# away through their ARCH_* dependencies.
for sym in $platforms; do
	[ "$sym" = ARCH_QCOM ] || ./scripts/config -d "$sym"
done
if [ "$1" = arm ]; then
	./scripts/config -e ARM_LPAE -d ARCH_IPQ40XX -d ARCH_MSM8909 -d ARCH_MSM8916 \
		-d ARCH_MSM8960 -d ARCH_MSM8974 -d ARCH_MSM8X60 -d ARCH_MDM9615
fi
# Subsystems an access point has no hardware for.
./scripts/config -d SOUND -d DRM -d FB -d MEDIA_SUPPORT -d BT -d CAN -d NFC \
	-d INPUT_TOUCHSCREEN -d USB_GADGET -d STAGING -d SLIMBUS -d QCOM_APR -d QCOM_IPA -d CMA
./scripts/config -e IIO -m IIO_ST_ACCEL_3AXIS -m IIO_ST_ACCEL_I2C_3AXIS
if [ "$1" = nss ]; then
	# What the NSS host drivers hook into (the NSS firmware DMAs to physical
	# addresses, and the IPQ5018 has no IOMMU); mac80211/ath11k are built from
	# backports, which also provides qmi_helpers - so nothing in the kernel may
	# build its own.
	./scripts/config -e SKB_RECYCLER -e SKB_RECYCLER_MULTI_CPU -e NF_CONNTRACK_DSCPREMARK_EXT \
		-e NET_CLS_ACT -e NF_CONNTRACK_EVENTS -e NF_CONNTRACK_MARK \
		-e IP_MROUTE -e IPV6_MROUTE -m IFB -e CFG80211_HEADERS -d CFG80211 -d MAC80211 -d IOMMU_SUPPORT \
		-d QCOM_SYSMON -d QCOM_PDR_HELPERS -d QCOM_PD_MAPPER
	# Every link type ECM and the NSS clients can offload needs its kernel side.
	./scripts/config -m PPP -m PPPOE -m PPTP -m NF_CONNTRACK_PPTP -m L2TP -e L2TP_V3 -m PPPOL2TP -m L2TP_ETH \
		-m BONDING -m MACVLAN -m NET_IPIP -m NET_IPGRE_DEMUX -m NET_IPGRE -e NET_IPGRE_BROADCAST -m IPV6_GRE \
		-m IPV6_SIT -e IPV6_SIT_6RD -m IPV6_TUNNEL -m XFRM_USER -m INET_ESP -m INET_ESP_OFFLOAD \
		-m INET6_ESP -m INET6_ESP_OFFLOAD
fi
make -s olddefconfig
cp .config "$here/config-$(make -s kernelversion)-u6e-$1"

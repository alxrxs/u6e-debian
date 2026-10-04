#!/bin/bash
# Turn a Debian rootfs into the U6-Enterprise RAM-boot set:
#   prep-rootfs.sh arm   -> out-arm/{zImage,u6e.dtb,u6e.initrd}           (rootfs-armhf, linux-arm)
#   prep-rootfs.sh arm64 -> out-arm64/{shim.bin,Image,u6e.dtb,u6e.initrd} (rootfs, linux-7.2.8)
#   prep-rootfs.sh nss   -> out-nss/{shim.bin,Image,u6e.dtb,u6e.initrd}   (rootfs, linux-7.2.8
#                           + the NSS drivers, wireless backports and NSS firmware from nss/build.sh)
# Run as root after that kernel's build; boot the output with boot/go8.sh.
# Site details (addresses, VLANs, keys, the blobs checkout) come from site.conf.
set -euo pipefail
cd "$(dirname "$0")"
. ./site.conf
MGMT_IF=vlan$MGMT_VLAN CLIENT_IF=vlan$CLIENT_VLAN
WIFI_VLANS=${WIFI_VLANS:-$CLIENT_VLAN}
case " $WIFI_VLANS " in *" $CLIENT_VLAN "*) ;; *) echo "WIFI_VLANS must include CLIENT_VLAN" >&2; exit 1 ;; esac
MGMT_IP=${MGMT_ADDR%/*}
MGMT_BCAST=$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_interface(sys.argv[1]).network.broadcast_address)' "$MGMT_ADDR")
INITRD_ADDR=0x52200000   # must match go8.sh
case "${1:-}" in
	arm)   RF=rootfs-armhf K=linux-arm   X=arm-linux-gnueabihf- IMG=arch/arm/boot/zImage
	       DTB=linux-arm/arch/arm/boot/dts/qcom/qcom-ipq5018-ubnt-u6-enterprise.dtb ;;
	arm64) RF=rootfs       K=linux-7.2.8 X=aarch64-linux-gnu-   IMG=arch/arm64/boot/Image
	       DTB=linux-7.2.8/arch/arm64/boot/dts/qcom/ipq5018-ubnt-u6-enterprise.dtb ;;
	nss)   RF=rootfs       K=linux-7.2.8 X=aarch64-linux-gnu-   IMG=arch/arm64/boot/Image
	       DTB=linux-7.2.8/arch/arm64/boot/dts/qcom/ipq5018-ubnt-u6-enterprise.dtb ;;
	*) echo "usage: $0 arm|arm64|nss" >&2; exit 2 ;;
esac
MODE=$1 OUT=out-$1
R=$(cat $K/include/config/kernel.release)

# Identity, access, console.
echo "$AP_HOSTNAME" > $RF/etc/hostname
install -d -m0700 $RF/root/.ssh
install -m0600 "$ROOT_AUTHORIZED_KEYS" $RF/root/.ssh/authorized_keys
install -d $RF/etc/systemd/system/serial-getty@ttyMSM0.service.d
printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --keep-baud 115200 %%I $TERM\n' \
	> $RF/etc/systemd/system/serial-getty@ttyMSM0.service.d/autologin.conf
rm -f $RF/init
ln -s /sbin/init $RF/init

# Network: mirror stock - management is a tagged VLAN on the uplink with the
# controller's static config (no address on the untagged side).
N=$RF/etc/systemd/network
rm -f $N/*.network $N/*.netdev $N/*.link
{
	printf '[Match]\nType=ether\n\n[Network]\nVLAN=%s\n' $MGMT_IF
	printf 'VLAN=vlan%s\n' $WIFI_VLANS
	printf 'LinkLocalAddressing=no\n'
} > $N/10-uplink.network
# Wi-Fi clients: each VLAN they can land in is bridged, unaddressed; hostapd
# adds the radios (and RADIUS-assigned clients' interfaces) to the bridges.
for v in $WIFI_VLANS; do
	printf '[NetDev]\nName=vlan%s\nKind=vlan\n\n[VLAN]\nId=%s\n' $v $v > $N/20-vlan$v.netdev
	printf '[Match]\nName=vlan%s\n\n[Network]\nBridge=br%s\nLinkLocalAddressing=no\n' $v $v > $N/20-vlan$v.network
	printf '[NetDev]\nName=br%s\nKind=bridge\n' $v > $N/25-br$v.netdev
	printf '[Match]\nName=br%s\n\n[Network]\nLinkLocalAddressing=no\nConfigureWithoutCarrier=yes\n' $v > $N/25-br$v.network
done
# Stable names by device path (PCI domains are pinned in the DT): the uplink
# GMAC is lan, which the NSS glue arms by name; nss mode creates the radio
# interfaces under these names itself.
printf '[Match]\nPath=platform-39d00000.ethernet\n\n[Link]\nName=lan\n' > $N/30-lan.link
printf '[Match]\nPath=platform-c000000.wifi\n\n[Link]\nName=wlan24\n' > $N/30-wlan24.link
printf '[Match]\nPath=*-pci-0000:01:00.0\nType=wlan\n\n[Link]\nName=wlan5\n' > $N/30-wlan5.link
printf '[Match]\nPath=*-pci-0001:01:00.0\nType=wlan\n\n[Link]\nName=wlan6\n' > $N/30-wlan6.link
printf '[NetDev]\nName=%s\nKind=vlan\n\n[VLAN]\nId=%s\n' $MGMT_IF $MGMT_VLAN > $N/20-$MGMT_IF.netdev
printf '[Match]\nName=%s\n\n[Network]\nAddress=%s\nGateway=%s\nDNS=%s\nDomains=%s\nNTP=%s\n' \
	$MGMT_IF "$MGMT_ADDR" "$MGMT_GW" "$MGMT_DNS" "$MGMT_DOMAIN" "$MGMT_NTP" > $N/20-$MGMT_IF.network
W=$RF/etc/systemd/system/multi-user.target.wants
for u in systemd-networkd systemd-resolved; do ln -sf /usr/lib/systemd/system/$u.service $W/$u.service; done

# Boot traces on raw eMMC sectors past the last partition (survive the
# fallback to stock): early marker at 5000000, full log at 5001000.
cat > $RF/usr/local/sbin/u6e-bootlog <<'LOG'
#!/bin/sh
# Full boot trace once the system is up; raw sectors only, never stock's filesystems.
{
	echo "=== U6E Debian boot $(date -u +%FT%TZ) ==="
	uname -a
	echo "--- cmdline"; cat /proc/cmdline
	echo "--- links"; ip -br link
	echo "--- addrs"; ip -br addr
	echo "--- routes"; ip route
	echo "--- failed units"; systemctl --no-pager --failed | head -20
	echo "--- dmesg"; dmesg
} 2>&1 | head -c 1000000 | dd of=/dev/mmcblk0 bs=512 seek=5001000 conv=fsync,sync 2>/dev/null
LOG
chmod 0755 $RF/usr/local/sbin/u6e-bootlog
cat > $RF/etc/systemd/system/u6e-bootlog.service <<'UNIT'
[Unit]
Description=U6E boot trace to eMMC
After=multi-user.target network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/u6e-bootlog
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
ln -sf /etc/systemd/system/u6e-bootlog.service $W/u6e-bootlog.service
cat > $RF/usr/local/sbin/u6e-bootmark <<'MARK'
#!/bin/sh
# Proof of life independent of systemd ordering: a marker as soon as the eMMC
# exists, then at 120 s the pending jobs and dmesg (shows what a stall waits on).
for _ in $(seq 120); do [ -b /dev/mmcblk0 ] && break; sleep 1; done
mark() { head -c 500000 | dd of=/dev/mmcblk0 bs=512 seek=5000000 conv=fsync,sync 2>/dev/null; }
{ echo "=== U6E early $(date -u +%FT%TZ) $(uname -r)"; dmesg; } | mark
sleep 120
{ echo "=== U6E +120s $(uname -r)"; systemctl list-jobs --no-pager 2>&1 | head -40; systemctl --failed --no-pager 2>&1 | head -20; dmesg; } | mark
MARK
chmod 0755 $RF/usr/local/sbin/u6e-bootmark
cat > $RF/etc/systemd/system/u6e-bootmark.service <<'UNIT'
[Unit]
Description=U6E early boot marker on eMMC
DefaultDependencies=no

[Service]
Type=exec
ExecStart=/usr/local/sbin/u6e-bootmark

[Install]
WantedBy=sysinit.target
UNIT
install -d $RF/etc/systemd/system/sysinit.target.wants
ln -sf /etc/systemd/system/u6e-bootmark.service $RF/etc/systemd/system/sysinit.target.wants/u6e-bootmark.service

# A hang must end in a warm reset (back to stock, pstore kept): systemd pets the
# hardware watchdog, the kernel panics on soft/hard lockups and on an oops
# (panic=10 reboots).
install -d $RF/etc/systemd/system.conf.d
printf '[Manager]\nRuntimeWatchdogSec=30s\nRebootWatchdogSec=2min\n' > $RF/etc/systemd/system.conf.d/u6e-watchdog.conf
printf 'kernel.panic_on_oops = 1\n' > $RF/etc/sysctl.d/u6e-panic.conf

# Kernel log live on the wire: netconsole to the management VLAN's broadcast
# address, so a hang that ends in the vendor's crash-dump mode (no reset, no
# pstore) still leaves its last messages; capture them on any host on that
# segment with tcpdump -A 'vlan <MGMT_VLAN> and udp port 6666'.
cat > $RF/etc/systemd/system/u6e-netconsole.service <<UNIT
[Unit]
Description=U6E kernel log to the management VLAN's broadcast (netconsole)
After=systemd-networkd.service
Wants=systemd-networkd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sh -c 'until ip -4 addr show $MGMT_IF 2>/dev/null | grep -q $MGMT_IP; do sleep 1; done'
ExecStart=/usr/sbin/modprobe netconsole
ExecStart=/bin/sh -c 'T=/sys/kernel/config/netconsole/u6e; mkdir -p \$T && echo $MGMT_IF > \$T/dev_name && echo $MGMT_IP > \$T/local_ip && echo $MGMT_BCAST > \$T/remote_ip && echo 6666 > \$T/remote_port && echo 1 > \$T/enabled'
ExecStart=/usr/bin/dmesg -n 8

[Install]
WantedBy=multi-user.target
UNIT
ln -sf /etc/systemd/system/u6e-netconsole.service $RF/etc/systemd/system/multi-user.target.wants/u6e-netconsole.service

# Status LED as the site sets it (AP_LED: off, blue or white); the DTS lights
# the blue one from boot (default-state "on").
case $AP_LED in off | blue | white) ;; *) echo "AP_LED must be off, blue or white" >&2; exit 1 ;; esac
cat > $RF/etc/systemd/system/u6e-leds.service <<'UNIT'
[Unit]
Description=U6E status LED
DefaultDependencies=no
After=systemd-udev-settle.service systemd-udevd.service
Before=sysinit.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'for l in /sys/class/leds/*; do echo none > $l/trigger; echo 0 > $l/brightness; done; [ @LED@ = off ] || echo 1 > /sys/class/leds/@LED@:status/brightness'

[Install]
WantedBy=sysinit.target
UNIT
install -d $RF/etc/systemd/system/sysinit.target.wants
sed -i "s/@LED@/$AP_LED/g" $RF/etc/systemd/system/u6e-leds.service
ln -sf /etc/systemd/system/u6e-leds.service $RF/etc/systemd/system/sysinit.target.wants/u6e-leds.service

# The AP keeps no logs (the journal is in RAM): systemd-netlogd sends the whole
# journal to the site's syslog collector (LOG_SERVER, address:port), and a
# timer logs the AP's state every 5 minutes, so a long run can be read back.
install -d $RF/etc/systemd/netlogd.conf.d
printf '[Network]\nAddress=%s\nProtocol=udp\nLogFormat=rfc5424\n' "$LOG_SERVER" \
	> $RF/etc/systemd/netlogd.conf.d/u6e.conf
ln -sf /usr/lib/systemd/system/systemd-netlogd.service $W/systemd-netlogd.service
cat > $RF/usr/local/sbin/u6e-stats <<'STATS'
#!/bin/sh
# One line of the AP's state for the syslog collector: load, free memory, the
# clients of each BSS, the thermal zones and the Wi-Fi firmware crashes so far.
sta=$(for c in /run/hostapd/*; do i=${c##*/}; printf '%s=%s ' $i "$(hostapd_cli -p /run/hostapd -i $i list_sta 2>/dev/null | wc -l)"; done)
temp=$(for z in /sys/class/thermal/thermal_zone*; do printf '%s=%s ' "$(cat $z/type)" $(($(cat $z/temp) / 1000)); done)
logger -t u6e-stats "load=$(cut -d' ' -f1 /proc/loadavg) memavail_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo) fw_crashes=$(dmesg | grep -c 'firmware crashed') clients: ${sta}temps: $temp"
STATS
chmod 0755 $RF/usr/local/sbin/u6e-stats
printf '[Unit]\nDescription=U6E state to the log\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/u6e-stats\n' \
	> $RF/etc/systemd/system/u6e-stats.service
printf '[Unit]\nDescription=U6E state to the log every 5 minutes\n\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=5min\n\n[Install]\nWantedBy=timers.target\n' \
	> $RF/etc/systemd/system/u6e-stats.timer
install -d $RF/etc/systemd/system/timers.target.wants
ln -sf /etc/systemd/system/u6e-stats.timer $RF/etc/systemd/system/timers.target.wants/u6e-stats.timer

# The boot that brought this image up was one-shot: U-Boot disarmed it before
# starting us. u6e-arm re-arms it from the steps go8.sh staged, or with "disarm"
# hands the next boot to stock; fw_setenv writes only the U-Boot env (mtd6).
printf '/dev/mtd6 0x0 0x10000 0x1000\n' > $RF/etc/fw_env.config

# fastfetch shows the board, so it shows the board's logo too. A config file
# replaces the default module list, so let fastfetch write out its own.
install -d $RF/etc/xdg/fastfetch
rm -f $RF/etc/xdg/fastfetch/config.jsonc
chroot $RF fastfetch -c none -l unifi --gen-config /etc/xdg/fastfetch/config.jsonc >/dev/null
cat > $RF/usr/local/sbin/u6e-arm <<'ARM'
#!/bin/sh
set -e
cur=$(fw_printenv -n bootcmd_real 2>/dev/null || true)
if [ "${1:-}" = disarm ]; then
	[ "$cur" = bootubnt ] || fw_setenv bootcmd_real bootubnt
	exit 0
fi
fw_printenv -n u8b >/dev/null 2>&1 || { echo "u6e-arm: no staged boot (u8b)" >&2; exit 1; }
steps=$(fw_printenv | sed -n 's/^\(u8[0-9]\)=.*/\1/p' | sort | sed 's/.*/run &;/' | tr '\n' ' ')
want="setenv bootcmd_real bootubnt; saveenv; ${steps}run u8b"
[ "$cur" = "$want" ] || fw_setenv bootcmd_real "$want"
ARM
chmod 0755 $RF/usr/local/sbin/u6e-arm

# Management network up 3 minutes after boot: with U6E_PERSIST the image re-arms
# itself once, so a reboot or power cut comes back here. None: disarm, put the
# journal into pstore and warm-reboot, so the fallback to stock keeps the
# evidence (boot/ramoops.sh). ARP, not ICMP: a gateway may well drop pings.
cat > $RF/usr/local/sbin/u6e-netcheck <<'CHECK'
#!/bin/sh
ping -c1 -W2 @MGMT_GW@ >/dev/null 2>&1
if ip neigh show @MGMT_GW@ | grep -qE 'REACHABLE|STALE|DELAY|PROBE'; then
	[ @PERSIST@ = 1 ] && [ ! -e /run/u6e-armed ] && /usr/local/sbin/u6e-arm && touch /run/u6e-armed
	exit 0
fi
/usr/local/sbin/u6e-arm disarm
{ echo "u6e-netcheck: no gateway at $(cut -d' ' -f1 /proc/uptime)s; links:"; ip -br link; ip -br addr; ip neigh
  mount -t debugfs none /sys/kernel/debug 2>/dev/null; D=/sys/kernel/debug/qca-nss-drv/stats
  grep -iE 'uniphy|gmac1|cmn_pll|ubi32' /sys/kernel/debug/clk/clk_summary; head -20 /sys/kernel/debug/clk/clk_orphan_summary
  ip -s -d link show lan; tc -s qdisc show dev lan; ethtool -S lan | grep -vE ': 0$'
  echo "== dwmac-nss"; cat /sys/kernel/debug/qca-dwmac-nss/status 2>&1 | head -n 40
  for f in n2h drv eth_rx gmac dma unaligned cpu_load_ubi; do echo "== nss $f"; grep -vE ' = 0 ' "$D/$f" 2>/dev/null | head -40; done
  echo "== nss irqs"; grep -E 'nss' /proc/interrupts
  echo "== nss n2hcfg"; sysctl -a 2>/dev/null | grep -E '^dev\.nss\.(n2hcfg|clock)'
  echo "== nss meminfo"; grep -vE '^\s*$' /sys/kernel/debug/qca-nss-drv/meminfo/core0 2>&1 | head -n 40
  echo "== nss stats nodes"; ls "$D" | tr '\n' ' '; echo
  echo "== lan offloads"; ethtool -k lan | grep -E 'vlan|rx-|scatter'
  echo "== @MGMT_IF@"; cat /proc/net/vlan/@MGMT_IF@ 2>&1 | grep -iE 'total|bytes|packets'
  echo "== arp on lan"; timeout 8 tcpdump -nn -e -c 20 -i lan arp 2>&1 | tail -n 22
  journalctl -b --no-pager -o short-monotonic | grep -vE 'mem_seg|board name|: 000000[0-9a-f]0: ' | tail -n 700
} | head -c 120000 > /dev/pmsg0
systemctl reboot
CHECK
sed -i "s/@MGMT_GW@/$MGMT_GW/g; s/@MGMT_IF@/$MGMT_IF/g; s/@PERSIST@/${U6E_PERSIST:-0}/g" $RF/usr/local/sbin/u6e-netcheck
chmod 0755 $RF/usr/local/sbin/u6e-netcheck
printf '[Unit]\nDescription=U6E reboot to stock when the management network is lost\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/u6e-netcheck\n' \
	> $RF/etc/systemd/system/u6e-netcheck.service
printf '[Unit]\nDescription=U6E management network check\n\n[Timer]\nOnBootSec=180\nOnUnitActiveSec=60\n\n[Install]\nWantedBy=timers.target\n' \
	> $RF/etc/systemd/system/u6e-netcheck.timer
install -d $RF/etc/systemd/system/timers.target.wants
ln -sf /etc/systemd/system/u6e-netcheck.timer $RF/etc/systemd/system/timers.target.wants/u6e-netcheck.timer

# Wi-Fi: per-unit calibration is written from ART at every boot, before anything
# loads ath11k; board-2.bin adds the U6-Enterprise BDF variants (fw/mk-board2.sh).
install -m0755 u6e-caldata $RF/usr/local/sbin/u6e-caldata
cat > $RF/etc/systemd/system/u6e-caldata.service <<'UNIT'
[Unit]
Description=U6E ath11k calibration data from ART
DefaultDependencies=no
Before=systemd-modules-load.service systemd-udev-trigger.service sysinit.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/u6e-caldata
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
UNIT
ln -sf /etc/systemd/system/u6e-caldata.service $RF/etc/systemd/system/sysinit.target.wants/u6e-caldata.service
for c in IPQ5018 QCN9074; do
	install -m0644 fw/out/$c/board-2.bin $RF/usr/lib/firmware/ath11k/$c/hw1.0/board-2.bin
done
# IPQ5018 WCSS: Qualcomm's newest published build (quic/upstream-wifi-fw); unlike
# linux-firmware's 2.6.0.1 it carries the user-PD segments the Wi-Fi firmware runs in.
rm -f $RF/usr/lib/firmware/ath11k/IPQ5018/hw1.0/q6_fw.* $RF/usr/lib/firmware/ath11k/IPQ5018/hw1.0/m3_fw.*
WCSS=$BLOBS/wifi/firmware/ipq5018-WLAN.HK.2.7.0.1-01744
install -m0644 "$WCSS"/q6_fw.* "$WCSS"/m3_fw.* $RF/usr/lib/firmware/ath11k/IPQ5018/hw1.0/

# The controller comes up with the NVM's placeholder address; give it the one
# the stock firmware uses, the board's base MAC + 4, before bluetoothd powers it.
cat > $RF/usr/local/sbin/u6e-btaddr <<'BTADDR'
#!/bin/sh
base=$(cat /sys/class/net/lan/address) || exit 1
addr=$(printf '%012x' $((0x$(echo "$base" | tr -d :) + 4)) | sed 's/../&:/g; s/:$//')
# btmgmt is an interactive shell: it only answers on a terminal, hence script.
mgmt() { timeout 5 script -qec "btmgmt --index 0 $*" /dev/null; }
for _ in $(seq 30); do
	mgmt info | grep -qi "addr $addr" && exit 0
	mgmt public-addr "$addr" >/dev/null
	sleep 2
done
echo "u6e-btaddr: could not set $addr" >&2
exit 1
BTADDR
chmod 0755 $RF/usr/local/sbin/u6e-btaddr
cat > $RF/etc/systemd/system/u6e-btaddr.service <<'UNIT'
[Unit]
Description=U6E Bluetooth public address (base MAC + 4)
After=systemd-udev-settle.service systemd-networkd.service
Before=bluetooth.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/u6e-btaddr
RemainAfterExit=yes

[Install]
WantedBy=bluetooth.target
UNIT
install -d $RF/etc/systemd/system/bluetooth.target.wants
ln -sf /etc/systemd/system/u6e-btaddr.service $RF/etc/systemd/system/bluetooth.target.wants/u6e-btaddr.service

# Bring-up diagnostics: ath11k AHB/BOOT/QMI debug and the WCSS IPC path's pr_debug.
install -d $RF/etc/modprobe.d
printf '%s\n' 'options ath11k debug_mask=0x61' 'options qrtr dyndbg=+p' 'options qrtr_smd dyndbg=+p' \
	'options qcom_glink_smem dyndbg=+p' 'options qcom_q6v5_wcss_sec dyndbg=+p' > $RF/etc/modprobe.d/u6e-debug.conf

# wireless-regdb defaults to a database re-signed with Debian's key, which only
# Debian kernels trust; ours trusts the upstream signers, so use their copy.
ln -sf /lib/firmware/regulatory.db-upstream $RF/etc/alternatives/regulatory.db
ln -sf /lib/firmware/regulatory.db.p7s-upstream $RF/etc/alternatives/regulatory.db.p7s

# Kernel modules: only the closure of what this AP uses. In nss mode the NSS
# drivers and the backports wireless stack go in updates/ first, so the closure
# also pulls in the kernel modules they need. NSS-only pieces are cleared
# first: arm64 and nss share the rootfs.
rm -rf modstage $RF/usr/lib/modules/* $RF/etc/modprobe.d/u6e-nss.conf \
	$RF/etc/udev/rules.d/80-u6e-wlan.rules $RF/etc/systemd/system/u6e-nss.service $RF/etc/systemd/system/multi-user.target.wants/u6e-nss.service
make -s -C $K ARCH=${MODE/nss/arm64} CROSS_COMPILE=$X INSTALL_MOD_PATH=$PWD/modstage INSTALL_MOD_STRIP=1 modules_install
M=$PWD/modstage/lib/modules/$R
WANT="netconsole qcom_q6v5_mpd qcom_q6v5_wcss_sec qrtr-smd qcrypto st_accel_i2c phy-qcom-m31 qrtr qrtr-mhi vxlan macsec bridge 8021q nf_tables nft_ct nft_chain_nat nft_nat nft_masq nft_reject_inet nft_fib_inet nft_log nft_limit nf_conntrack tun wireguard sch_htb sch_tbf sch_fq_codel sch_prio sch_ingress cls_u32 cls_fw cls_matchall cls_flower act_police act_skbedit act_connmark act_mirred ifb btqcomipc"
if [ $MODE = nss ]; then
	install -d "$M/updates"
	cp nss/out/$R/*.ko "$M/updates/"
	find nss/src/backports -name '*.ko' -print0 | while IFS= read -r -d '' f; do
		${X}strip --strip-debug -o "$M/updates/$(basename "$f")" "$f"
	done
	depmod -b modstage "$R"
	WANT="$WANT $(ls "$M/updates" | sed 's/\.ko$//')"
else
	WANT="$WANT ath11k_pci ath11k_ahb"
fi
for m in $WANT; do /sbin/modprobe -S "$R" -d modstage --show-depends $m; done | awk '/^insmod/{print $2}' | sort -u > modules.keep
install -d $RF/usr/lib/modules/$R
(cd "$M" && cp modules.order modules.builtin modules.builtin.modinfo "$OLDPWD/$RF/usr/lib/modules/$R/")
while read -r f; do install -D -m0644 "$f" "$RF/usr/lib/modules/$R/${f#"$M"/}"; done < modules.keep
rm -rf modstage
if [ $MODE = nss ]; then
	# Nothing NSS loads on its own: u6e-nss.service brings the plane up in
	# order once networkd has configured lan, and only then loads the radios.
	# The firmware computes the TX checksums (12.2 honours the host's flags),
	# so the glue keeps checksum offload and TSO on lan.
	printf '%s\n' 'options ath11k nss_offload=1 frame_mode=2' 'options qca-dwmac-nss ifname=lan fw_if=1 fw_csum=1' \
		'blacklist ath11k_ahb' 'blacklist ath11k_pci' > $RF/etc/modprobe.d/u6e-nss.conf
	# The OpenWrt wireless stack makes no default interface (a station vif
	# taken through NSS offload hangs the NSS core); add each radio's as an AP.
	for r in c000000.wifi:wlan24 0000:01:00.0:wlan5 0001:01:00.0:wlan6; do
		printf 'ACTION=="add", SUBSYSTEM=="ieee80211", KERNELS=="%s", RUN+="/usr/sbin/iw phy %%k interface add %s type __ap"\n' \
			"${r%:*}" "${r##*:}"
	done > $RF/etc/udev/rules.d/80-u6e-wlan.rules
fi
depmod -b $RF "$R"

# Firmware: ath11k for this board's radios, its Bluetooth, and regdb only.
FW=$RF/usr/lib/firmware
find $FW -mindepth 1 -maxdepth 1 ! -name ath11k ! -name 'regulatory.db*' -exec rm -rf {} +
find $FW/ath11k -mindepth 1 -maxdepth 1 ! -name 'IPQ5018*' ! -name QCN9074 -exec rm -rf {} +
# Bluetooth: the stock firmware (the split image TrustZone authenticates, and
# the NVM) under the qca/ names btqcomipc and btqca ask for.
install -d $FW/qca
install -m0644 "$BLOBS"/bt/firmware/bt_fw_patch.* "$BLOBS"/bt/firmware/mpnv10.bin $FW/qca/
if [ $MODE = nss ]; then
	install -m0644 nss/out/$R/firmware/qca-nss0-retail.bin $FW/
	ln -sf qca-nss0-retail.bin $FW/qca-nss0.bin
	# NSS start-up in the order kuncy7's nss-dwmac-up measured for the dwmac
	# data plane, for this 1 GB, 2-core board; each step reports its own failure.
	cat > $RF/usr/local/sbin/u6e-nss <<'NSS'
#!/bin/sh
s() { sysctl -q -w "$@" || echo "u6e-nss: sysctl $* failed" >&2; }
wait_for() { # <seconds> <what> <test...>
	t=$1 what=$2; shift 2
	until "$@"; do
		t=$((t - 1)); [ $t -gt 0 ] || { echo "u6e-nss: timed out waiting for $what" >&2; return 1; }
		sleep 1
	done
}
pin() { # <irq name> <cpu mask>
	irq=$(awk -v n="$1" '$NF == n {sub(":", "", $1); print $1; exit}' /proc/interrupts)
	[ -n "$irq" ] && echo "$2" > "/proc/irq/$irq/smp_affinity"
}
# The GMAC's RX filter (promiscuous for the client bridge, the VLAN filter) only
# reaches the hardware while the host owns it, and a takeover on a link networkd
# is still bouncing never delivers ingress: arm once lan is up, VLAN'd and bridged.
lan_ready() {
	[ "$(cat /sys/class/net/lan/operstate 2>/dev/null)" = up ] && [ -d /sys/class/net/@MGMT_IF@ ] &&
		[ -d /sys/class/net/@CLIENT_IF@/brport ] && [ $(($(cat /sys/class/net/lan/flags) & 0x100)) -ne 0 ]
}
core_up() { [ -r /sys/kernel/debug/qca-nss-drv/stats/n2h ]; }
plane_started() { grep -q started /sys/kernel/debug/qca-dwmac-nss/status; }
# The pool sysctls refuse writes until the core reports INITIALIZED.
pools() { sysctl -q -w dev.nss.n2hcfg.extra_pbuf_core0=3203072 2>/dev/null; }
mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug
modprobe -a qca-dwmac-nss qca-nss-drv
wait_for 120 "lan configured" lan_ready || exit 1
sleep 2
echo 2 > /sys/kernel/debug/qca-dwmac-nss/fw_mask
wait_for 30 "the NSS core" core_up || exit 1
wait_for 30 "lan on the firmware data plane" plane_started
# Receive steering: one NSS queue per core.
pin nss_queue0 1; pin nss_queue1 2; pin nss_empty_buf_sos 1; pin nss_empty_buf_queue 1
s dev.nss.rps.enable=1 dev.nss.rps.hash_bitmap=3
# Host buffer pool and queue limits: the values the vendor firmware runs this
# AP with (its NSS starves for receive buffers on the driver defaults).
s dev.nss.clock.auto_scale=0
wait_for 30 "the pbuf sysctls" pools
s dev.nss.n2hcfg.n2h_empty_pool_buf_core0=8704 dev.nss.n2hcfg.n2h_low_water_core0=4352
s dev.nss.n2hcfg.n2h_high_water_core0=31648 dev.nss.n2hcfg.n2h_wifi_pool_buf=4096
s dev.nss.n2hcfg.n2h_queue_limit_core0=256
s dev.nss.general.logbuf=1024
# Wi-Fi offload registers wifili with the running core.
modprobe -a ath11k_ahb ath11k_pci
# Every offload manager; vlan-mgr replays the existing VLANs onto the
# interface numbers the takeover created. The crypto and GRE test harnesses
# ship but are not loaded.
modprobe -a qca-nss-crypto qca-nss-cfi-cryptoapi qca-mcs nat46 qca-nss-qdisc act_nssmirred qca-nss-vlan \
	qca-nss-lag-mgr qca-nss-vxlanmgr qca-nss-pvxlanmgr qca-nss-gre qca-nss-eogremgr qca-nss-clmapmgr \
	qca-nss-pppoe qca-nss-pptp qca-nss-l2tpv2 qca-nss-tunipip6 qca-nss-tun6rd qca-nss-map-t \
	qca-nss-ipsecmgr qca-nss-ipsec-xfrm qca-nss-match qca-nss-mirror qca-nss-wifi-meshmgr
# Flow offload: ECM in NSS mode; its conntrack settings need conntrack loaded.
modprobe nf_conntrack
s net.netfilter.nf_conntrack_tcp_no_window_check=1 net.netfilter.nf_conntrack_max=32768
modprobe ecm front_end_selection=1
modprobe qca-nss-netlink
NSS
	sed -i "s/@MGMT_IF@/$MGMT_IF/g; s/@CLIENT_IF@/$CLIENT_IF/g" $RF/usr/local/sbin/u6e-nss
	chmod 0755 $RF/usr/local/sbin/u6e-nss
	cat > $RF/etc/systemd/system/u6e-nss.service <<'UNIT'
[Unit]
Description=U6E NSS offload: data plane, Wi-Fi offload, managers, ECM flow acceleration
After=systemd-networkd.service
Wants=systemd-networkd.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/u6e-nss

[Install]
WantedBy=multi-user.target
UNIT
	ln -sf /etc/systemd/system/u6e-nss.service $RF/etc/systemd/system/multi-user.target.wants/u6e-nss.service
fi

# Pack: a reproducible zstd initrd (fixed mtimes, renumbered inodes) with the
# paths this script rewrites last, so go8.sh's chunk compare only rewrites the
# tail of the image on the eMMC; and the DTB carrying its location.
rm -rf $OUT; install -d $OUT
TAIL='usr/lib/firmware usr/lib/modules etc usr/local'
find $RF -exec touch -h -d @1767225600 {} +
(cd $RF && {
	find . -print0 | sort -z | grep -zvE "^\./(${TAIL// /|})(/|\$)"
	for d in $TAIL; do find ./$d -print0 | sort -z; done
} | cpio --null -o -H newc --quiet --reproducible) | zstd -q -19 -T0 > $OUT/u6e.initrd
if [ $MODE = arm ]; then
	cp $K/$IMG $OUT/zImage
else
	cp $K/$IMG $OUT/Image
	shim/build.sh && cp shim/shim.bin $OUT/shim.bin
fi
cp $DTB $OUT/u6e.dtb
S=$(stat -c %s $OUT/u6e.initrd)
fdtput -t x $OUT/u6e.dtb /chosen linux,initrd-start $INITRD_ADDR
fdtput -t x $OUT/u6e.dtb /chosen linux,initrd-end "$(printf '%#x' $((INITRD_ADDR + S)))"
# A persistent image re-arms its own boot, so the U-Boot env (and only it) must
# be writable; every other SPI partition stays read-only.
[ "${U6E_PERSIST:-0}" = 1 ] && fdtput -d $OUT/u6e.dtb /soc@0/spi@78b5000/flash@0/partitions/partition@110000 read-only
echo "release $R, modules $(wc -l < modules.keep), rootfs $(du -sh $RF | cut -f1)"
ls -la $OUT; sha256sum $OUT/*

# Keep every image (~85 MB): images/<time>-<kernel>-<backports>-<AP>/ can be staged
# again with go8.sh without a rebuild; MANIFEST records what went into it.
g() { git -c safe.directory='*' -C "$1" log -1 --format='%h %s'; }
A=images/$(date +%Y%m%d-%H%M%S)-$MODE-$(git -c safe.directory='*' -C $K rev-parse --short HEAD)
[ $MODE = nss ] && A=$A-$(git -c safe.directory='*' -C backports-7.2 rev-parse --short HEAD)
A=$A-${U6E_AP:-default}
install -d "$A"; cp -a $OUT/. "$A"/
{ echo "ap:        ${U6E_AP:-default} ($AP_HOSTNAME, $MGMT_ADDR)"
  echo "kernel:    $(g $K)"
  [ $MODE = nss ] && echo "backports: $(g backports-7.2)"
  echo "debian-ap: $(g .)"
  echo "hostapd:   $(dpkg-query --admindir=$RF/var/lib/dpkg -W -f '${Version}' hostapd)"
  sha256sum $OUT/*; } > "$A"/MANIFEST
echo "kept as $A"

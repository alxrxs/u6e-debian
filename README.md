# Debian on the Ubiquiti UniFi U6 Enterprise

Debian 13 (trixie) with Linux 7.2 on the UniFi U6 Enterprise (IPQ5018: two Cortex-A53, an internal 2.4 GHz radio, two QCN9074 radios for 5 and 6 GHz, one 2.5 GbE port), run from RAM next to the untouched stock firmware, with Qualcomm's NSS offload doing the data plane: the NSS core owns the Ethernet MAC (TSO and checksum offload on), all three radios run NSS Wi-Fi offload, ECM accelerates flows, and the NSS crypto engine serves the kernel crypto API.

Verified on hardware: the image boots in about 40 s, the NSS core takes the uplink, the three radios beacon, the 18 NSS crypto algorithms pass the kernel self-tests and every offload manager loads. Nothing is ever written to the SPI flash.

## Repositories

| Repository | What |
|---|---|
| `u6e-debian` (this) | Build scripts, the NSS package patch sets, the AArch64 TrustZone shim, the RAM-boot tooling |
| `u6e-linux` | The kernel: branch `u6e` (7.2.8 + the board, clock and NSS hook patches), `u6e-armv7` (the 32-bit build), `u6e-6.12` (the first NSS port) |
| `u6e-backports` | Wireless backports 7.2 (OpenWrt) with the NSS mac80211/ath11k series, branch `u6e-nss` |

Every imported patch keeps its author; a hand-ported one carries a note on what the port changed. The lists (`patches-7.2-nss.list`, `patches-bp72.list`) replay the series onto the upstream trees with `apply-list.sh`; `patches-local/` exports the board's own kernel patches, with George Moussalem's IPQ5018 Bluetooth series (v5, from the lists; 0013-0018) ahead of our fixes for it.

## Building

Inputs:
- `linux-7.2.8/` and `backports-7.2/`: checkouts of `u6e-linux` (branch `u6e`) and `u6e-backports` (branch `u6e-nss`).
- `site.conf`: copy `site.conf.example` and fill it in (addresses, VLANs, the stock login, the Wi-Fi test SSID).
- `$BLOBS` (from `site.conf`): the proprietary inputs, laid out as below. The NSS firmware itself is downloaded by `nss/build.sh` (sha256-pinned).

| `$BLOBS/` path | Source |
|---|---|
| `wifi/firmware/ipq5018-WLAN.HK.2.7.0.1-01744/` (`q6_fw.*`, `m3_fw.*`) | Qualcomm `quic/upstream-wifi-fw` |
| `wifi/board/linux-firmware/{IPQ5018,QCN9074}/` | linux-firmware's `ath11k/<chip>/hw1.0/board-2.bin`, unpacked with `fw/ath11k-bdencoder -e` |
| `wifi/board/stock-a654/bdwlan.{b23,ba3,ba4}` | the stock firmware's `/lib/firmware/platforms/a654/` |
| `bt/firmware/` (`bt_fw_patch.mdt` + `.b00`-`.b02`, `mpnv10.bin`) | the stock firmware's `/lib/firmware/IPQ5018/` |

Then, on an x86 host with the aarch64/armhf cross toolchains, `mmdebstrap`, `qemu-user-static` and `u-boot-tools`:

```sh
sudo pkg/iproute2-nss/build.sh     # Debian's iproute2 with the NSS qdiscs in tc -> pkg/iproute2-nss/out/
sudo pkg/hostapd/build.sh          # hostapd 2.12 (+ the 2026-5 fix) with every feature -> pkg/hostapd/out/
sudo ./mkrootfs.sh arm64           # Debian rootfs -> rootfs/
fw/mk-board2.sh                    # board-2.bin with the U6-E variants -> fw/out/
./config-u6e.sh nss                # kernel .config (also arm64 / arm without NSS)
make -C linux-7.2.8 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc) Image modules qcom/ipq5018-ubnt-u6-enterprise.dtb
nss/build.sh                       # NSS drivers, the wireless stack, NSS firmware
sudo ./prep-rootfs.sh nss          # -> out-nss/{shim.bin,Image,u6e.dtb,u6e.initrd}
```

`prep-rootfs.sh` packs the initrd reproducibly (fixed mtimes, the paths it rewrites last), so a rebuild changes only the tail of the image. It also keeps every image it makes under `images/<time>-<mode>-<kernel>[-<backports>]/` with a `MANIFEST` (commits, hostapd version, checksums), so an earlier build can be staged again with `go8.sh` without rebuilding.

## Booting

Ubiquiti's U-Boot is AArch32 and only `bootm`s its own signed FIT images, but `bootz` runs any armv7 zImage. `shim/` is a 208-byte zImage that makes the QSDK TrustZone call (`smc` 0x0200010F, `jump_kernel64`) which restarts the core in AArch64 EL1 at the arm64 `Image`.

`boot/go8.sh shim.bin u6e.dtb u6e.initrd Image`, run against the stock firmware, stages the four payloads as files in stock's `/tmp/log` (ext4 on the eMMC, kept across reboots), rewriting only the 64 KiB chunks that changed, maps their extents with `ext4map.py`, and writes one U-Boot environment batch: a `bootcmd_real` that first disarms itself, then reads the payloads, CRC-checks each and `bootz`es the shim. Reboot stock and the AP comes up in Debian; any reboot after that returns to stock. `boot/apstate.sh` tells which system is running.

What is ever written: files in `/tmp/log`, raw eMMC sectors past the last partition (5000000+) for boot traces, and on the SPI flash only the U-Boot environment partition. The device tree marks every SPI partition read-only; a persistent image's DTB lifts that for the environment alone.

### Persistent mode

Each boot `go8.sh` arms is one-shot: `bootcmd_real` disarms itself before it starts the image, so any reboot lands in stock. With `U6E_PERSIST=1` in `site.conf`, `u6e-netcheck` re-arms it (`u6e-arm`) the first time the management network is reachable after a boot, so reboots and power cuts come back into Debian. A boot that never reaches the network is not re-armed, and losing the network later disarms (`u6e-arm disarm`) before the netcheck reboot, so a broken image always falls back to stock instead of looping. `u6e-arm disarm` by hand hands the next boot to stock. Each Debian boot costs two writes of the 64 KiB environment: U-Boot's disarm and the re-arm. The payloads stay where `go8.sh` staged them, in stock's `/tmp/log`, which only stock writes to.

## On the AP

- `u6e-nss.service` brings NSS up in the order the hardware needs: once networkd has the uplink up, VLAN'd and bridged, it arms the GMAC (`qca-dwmac-nss` hands it to the firmware), sizes the firmware's buffer pools to stock's values, loads the radios with NSS offload, every offload manager, then ECM.
- `boot/wifi-up.sh` starts the test SSID on all three radios (country and channel plan from `site.conf`) with 802.11d/e/h/i/k/r/u/v/w (h also off DFS channels), MBO, beacon protection, the RFC 8325 QoS map and the 802.11ax features (beamforming, TWT, BSS colour, spatial reuse); the 2.4 and 5 GHz beacons announce the 6 GHz BSS.
- Recovery: a hang warm-resets (systemd watchdog, panic on lockups and oops); with no management network after 3 minutes `u6e-netcheck` writes its diagnosis to pstore and reboots into stock, where `boot/ramoops.sh` reads it back. The kernel log also goes to the management VLAN's broadcast address (netconsole, UDP 6666).
- `u6e-caldata` writes each radio's calibration from the AP's own ART partition at every boot.
- Bluetooth: the IPQ5018's own controller (`btqcomipc`, firmware loaded through TrustZone) is `hci0` for BlueZ; `u6e-btaddr` gives it the stock firmware's address, the base MAC + 4, before `bluetoothd` starts.
- The status light is two LEDs, `white:status` and `blue:status` in `/sys/class/leds`; blue comes on at boot.
- hostapd is 2.12 from `pkg/hostapd` (Debian's packaging, every feature built in, testing options off).
- Installed for the SSIDs, not yet configured: `tc` from `pkg/iproute2-nss` drives the NSS qdiscs (`nsshtb`, `nsstbl`, `nssfq_codel`, …; `accel_mode 0` shapes in the firmware), with the kernel's HTB/TBF/u32/police/skbedit/connmark modules for traffic the firmware hands back to Linux; `radsecproxy` carries hostapd's RADIUS (UDP only) over RadSec, and stays disabled until it has a configuration.
- `fastfetch` shows the board with the UniFi logo.

## Licence

The scripts are GPL-2.0-only; patches keep their authors' licences. `fw/ath11k-bdencoder` is qca-swiss-army-knife's (ISC).

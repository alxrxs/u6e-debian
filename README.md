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
- `site.conf`: copy `site.conf.example` and fill it in (addresses, VLANs, the stock login, the SSIDs).
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
sudo pkg/hostapd/build.sh          # hostapd (pinned upstream main) with every feature -> pkg/hostapd/out/
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
- `boot/wifi-up.sh` starts the site's SSIDs (`WIFI_SSIDS` in `site.conf`: name, kind, bands, default VLAN; country and channel plan also from `site.conf`), each a BSS per radio it names, extra ones on locally administered BSSIDs. Three kinds: WPA3-Personal (SAE and SAE-EXT-KEY with FT, hash-to-element only, WPA3 transition disable); WPA3-Enterprise (802.1X with SHA-256 and FT-EAP, no periodic reauthentication); and WPA2-Personal plus RADIUS MAC authentication, without PMF, for clients that can do nothing newer (no MBO, OCE or FT there). hostapd itself talks RADIUS over TLS (RadSec, RFC 6614) to the site's RADIUS server with its client certificate, both pulled from the site into `/run` at each start, and puts a client whose RADIUS reply names a VLAN into that VLAN's bridge (`WIFI_VLANS`, each bridged by the image). CCMP-128 and GCMP-256 data encryption run in hardware, BIP-CMAC-128 for management frames in software; DTIM 1 on 2.4 GHz, 3 on 5 and 6 GHz. Every BSS has 802.11d/e/h/i/k/u/v (h also off DFS channels; k: neighbor reports listing the SSID's other radios, link measurement, BSS Load; v: BSS transition, WNM sleep, proxy ARP with the bridge doing client-to-client forwarding), multicast delivered to each client as unicast, a new group key whenever a client leaves, and never an in-place pairwise rekey (the driver can't replace a client's key safely: traffic stops until the client is dropped); the WPA3 ones also 802.11r/w (FT over the air, keys pulled between radios), operating channel validation, SSID protection, MBO, OCE and Wi-Fi QoS Management DSCP policies. The radios: 6 GHz as an indoor (LPI) AP whose Transmit Power Envelope carries the site's client PSD limit, 2.4 GHz OFDM only, an FTM responder (802.11mc ranging), 802.11ai FILS Discovery on 6 GHz, the RFC 8325 QoS map, the full HT/VHT capabilities for Wi-Fi 4/5 clients (LDPC, STBC, short guard interval, VHT beamforming, 11454-byte MPDUs) and the 802.11ax features (beamforming, TWT, BSS colour, spatial reuse); the 2.4 and 5 GHz beacons announce the 6 GHz BSSs. No beacon protection: clients that verify it drop every beacon the firmware sends.
- Recovery: a hang warm-resets (systemd watchdog, panic on lockups and oops); with no management network after 3 minutes `u6e-netcheck` writes its diagnosis to pstore and reboots into stock, where `boot/ramoops.sh` reads it back. The kernel log also goes to the management VLAN's broadcast address (netconsole, UDP 6666). The whole journal, hostapd included, goes to the site's syslog collector (`systemd-netlogd` to `LOG_SERVER`), and `u6e-stats` adds the AP's state every 5 minutes: load, free memory, clients per BSS, temperatures and Wi-Fi firmware crashes.
- `u6e-caldata` writes each radio's calibration from the AP's own ART partition at every boot.
- Bluetooth: the IPQ5018's own controller (`btqcomipc`, firmware loaded through TrustZone) is `hci0` for BlueZ; `u6e-btaddr` gives it the stock firmware's address, the base MAC + 4, before `bluetoothd` starts.
- The status light is two LEDs, `white:status` and `blue:status` in `/sys/class/leds`; the DTS lights blue at boot and `u6e-leds.service` sets them early in boot as the site's `AP_LED` says (off, blue or white).
- hostapd is upstream main pinned to one commit (newer than 2.12: AP-side Wi-Fi QoS Management DSCP policy) from `pkg/hostapd` (Debian's packaging, every feature built in, testing options off) with fifteen patches of ours, all for upstream and each with hwsim tests where hwsim can show the behaviour: `no_pri_sec_switch` is a config option; the RNR's 20 MHz PSD carries the 6 GHz client power limit (802.11-2024 11.49); a BSS Transition Management Query is answered with a candidate list and the Neighbor Report ANQP-element is generated (Wi-Fi Agile Multiband 3.5.1); a client's Link Measurement Request is answered (802.11k); the own neighbor report carries the Mobility Domain bit; the Estimated Service Parameters element (`esp=1`); Wi-Fi Optimized Connectivity AP for drivers where hostapd answers probes (`oce=4`: probe suppression, broadcast probe responses, beacons in place of probe responses, Transmit Power and IP Subnet attributes, co-located RNR and AP Channel Report, one MBO-OCE element on RSSI rejection; OCE 3.3's retry limit of 3 for unicast probe responses holds on 2.4 GHz, where the IPQ5018 firmware makes 4 attempts, but not on 5 GHz, where the QCN9074 firmware (WLAN.HK 0x290b8862) makes 9 and neither honours `WMI_PDEV_PARAM_PROBE_RESP_RETRY_LIMIT` nor survives a per-frame `retry_limit` in the management TX parameters); BSS Transition Management Requests carry the cellular data preference only to cellular-capable clients; a zero Medium Time for downlink TSPECs (WMM); and fixes for a DSCP policy crash and FILS Request Parameters parsing.
- Installed for the SSIDs, not yet configured: `tc` from `pkg/iproute2-nss` drives the NSS qdiscs (`nsshtb`, `nsstbl`, `nssfq_codel`, …; `accel_mode 0` shapes in the firmware), with the kernel's HTB/TBF/u32/police/skbedit/connmark modules for traffic the firmware hands back to Linux; `radsecproxy` carries hostapd's RADIUS (UDP only) over RadSec, and stays disabled until it has a configuration.
- `fastfetch` shows the board with the UniFi logo.

## Licence

The scripts are GPL-2.0-only; patches keep their authors' licences. `fw/ath11k-bdencoder` is qca-swiss-army-knife's (ISC).

# Debian on the Ubiquiti UniFi U6 Enterprise

This repository turns a UniFi U6 Enterprise Wi-Fi access point into a small Debian 13 (trixie) computer running Linux 7.2.8, with all three radios working as a full-featured Wi-Fi 6/6E access point.

The U6 Enterprise has a Qualcomm IPQ5018 chip (two ARM cores, an internal 2.4 GHz radio), two QCN9074 radios for 5 GHz and 6 GHz, and one 2.5 GbE network port. Debian runs entirely from RAM, started next to the untouched stock firmware, so the stock system is always one reboot away. Qualcomm's NSS (a separate network processor inside the chip) does the packet forwarding in hardware, including for Wi-Fi.

The only thing ever written to the SPI flash (the small chip holding the boot loader) is the boot loader's settings, which hold the command that starts Debian (see [Booting](#booting)).

## What you need

- An x86 Linux build machine with the aarch64 cross compiler (and the armhf one, for the 32-bit boot shim), `mmdebstrap`, `qemu-user-static` and `u-boot-tools`.
- SSH access to the stock firmware of each access point (the stock login set in `site.conf`).
- `site.conf`: your site's settings. Copy `site.conf.example` and fill it in; it is never committed. It holds:
  - the management network (VLAN, gateway, DNS, NTP, syslog collector) and the VLANs Wi-Fi clients land in;
  - the Wi-Fi plan: country, one line per SSID (name, kind, bands, default VLAN), channels, transmit power, and the optional 6 GHz Multiple BSSID setting;
  - how secrets are fetched: passphrases, the roaming key, the RADIUS-over-TLS certificate and the stock login are read by small shell functions, so they can come from a file or a password manager;
  - one block per access point (hostname, address, LED colour, Wi-Fi colours), and the test client for `test/`;
  - `U6E_PERSIST` (see [Booting](#booting)) and `BLOBS`, the location of the proprietary files below.
- `$BLOBS`: a separate private repository with the proprietary files the build reads from it. They are not redistributable, so they are not included here:

| Path under `$BLOBS/` | What it is |
|---|---|
| `wifi/firmware/ipq5018-WLAN.HK.2.7.0.1-01744/` | Wi-Fi firmware for the internal 2.4 GHz radio |
| `wifi/firmware/qcn9074-WLAN.HK.2.13-01309/` | Wi-Fi firmware for the 5 GHz and 6 GHz radios |
| `wifi/board/linux-firmware/{IPQ5018,QCN9074}/` | Board data (calibration tables) from linux-firmware |
| `wifi/board/stock-a654/` | Board data for this model, taken from the stock firmware |
| `bt/firmware/` | Bluetooth firmware, taken from the stock firmware |

The NSS firmware is downloaded by the build and checked against a pinned checksum.

## Quick start

```sh
cp site.conf.example site.conf    # then edit it
sudo ./deploy.sh                  # build everything and boot every access point in U6E_APS
sudo ./deploy.sh ap1 ap2          # or only the named ones
```

`deploy.sh` runs these steps in order and skips any whose inputs have not changed since the last run (it records them in `stamps/`; logs go to `log/`):

1. `trees.sh`: prepares the kernel and Wi-Fi driver sources (see [Sources and patches](#sources-and-patches)).
2. `fw/mk-board2.sh`: assembles the board data files for the radios.
3. `config-u6e.sh` and `make`: configures and builds the kernel.
4. `nss/build.sh`: builds the NSS drivers and the Wi-Fi stack, and fetches the NSS firmware.
5. `pkg/hostapd/build.sh`: builds hostapd (the program that runs the Wi-Fi networks) as a Debian package.
6. `pkg/iproute2-nss/build.sh`: builds Debian's `iproute2` with the NSS traffic-shaping options added to `tc`.
7. `mkrootfs.sh`: creates the Debian root filesystem.
8. For each access point: `prep-rootfs.sh` builds its image, `boot/stage.sh` boots it, and `deploy.sh` waits until all three radios are up.

Every image is kept in `images/` with a `MANIFEST` (versions and checksums), so an earlier build can be booted again without rebuilding.

## Sources and patches

The kernel and the Wi-Fi drivers are stored here as a download address plus a series of patches, not as copies of the upstream code:

- `kernel/`: Linux 7.2.8 (`kernel/source`) and 119 patches (`kernel/patches`) for this board and for NSS.
- `backports/`: OpenWrt's backports of the Linux 7.2 wireless stack (`backports/source`) and 192 patches (`backports/patches`) adding NSS Wi-Fi offload and fixes.

`./trees.sh` downloads each release (checked against its checksum), applies the patches as git commits and produces the working trees `linux-7.2.8/` and `backports-7.2/`. The commit IDs come out the same every time. To change something, commit in a tree and run `./export.sh kernel` (or `backports`) to turn your new commits back into patch files. `trees.sh` refuses to overwrite a tree whose work has not been exported.

Patches keep their original authors. We are sending our patches to the upstream projects (the kernel and hostapd).

## Booting

Ubiquiti's boot loader (U-Boot) is 32-bit and only starts its own signed images, but it will start any 32-bit ARM kernel. `shim/` is a tiny 32-bit program (208 bytes) that asks the chip's TrustZone (its built-in secure firmware) to restart the processor in 64-bit mode at our kernel.

`boot/go8.sh` does the staging while the stock firmware is running. It copies the shim, the kernel, the device tree and the initial filesystem into stock's data partition on the eMMC (changing only the parts that differ), and writes a one-shot U-Boot boot command that loads them. The next reboot starts Debian. The reboot after that returns to stock, because the command removes itself as it runs. `boot/stage.sh` does the whole cycle for one access point, from either system, and `boot/apstate.sh` tells you which system is running.

Persistent mode: with `U6E_PERSIST=1` in `site.conf`, the image re-arms the boot command once the management network is reachable (`u6e-netcheck` and `u6e-arm`), so reboots and power cuts come back into Debian. If the network never comes up, or is lost later, the boot command is removed and the access point returns to stock instead of looping. `u6e-arm disarm` does the same by hand. Each Debian boot in persistent mode writes the 64 KiB U-Boot settings area twice.

## What the access point does

Wi-Fi starts by itself on every boot (`u6e-wifi.service`), with nothing else on the network needed. `boot/wifi-up.sh` generates the configuration from `site.conf`, and can install a changed one on a running access point.

**Networks**
- Three kinds of SSID, each on the bands you choose: WPA3-Personal, WPA3-Enterprise, and WPA2-Personal with MAC-address authentication for old devices that can do nothing newer.
- Enterprise logins are checked by your RADIUS server over TLS ("RadSec") spoken directly by hostapd. RADIUS can also place each client in its own VLAN.
- Optional 6 GHz Multiple BSSID: all 6 GHz networks share one beacon.

**Roaming and client help**
- Fast roaming between radios and access points (802.11r).
- Roaming advice for clients (802.11k and 802.11v). The access points send each other lists of their networks every 10 seconds (`u6e-neighbors`), so clients are told about the others.
- Optimized Connectivity (OCE), Agile Multiband (MBO) and Wi-Fi QoS Management, which help clients pick the best band and mark their traffic correctly.
- Beacon protection on 5 GHz and 6 GHz, which stops forged beacons.
- Time-of-flight ranging for indoor location, 6 GHz discovery frames, and 6 GHz announcements on the 2.4 and 5 GHz beacons so clients find 6 GHz quickly.

**Speed**
- Packet forwarding, Wi-Fi offload and encryption run on the NSS processor.
- Multicast is sent to each client as unicast, and the access point answers ARP for its clients so broadcasts stay off the air.
- The usual Wi-Fi 4/5/6 speed features are enabled: beamforming, TWT and spatial reuse among them.

**Running it day to day**
- The whole system log goes to your syslog collector (the access point keeps logs only in RAM), the kernel log goes out over the network, and `u6e-stats` adds load, memory, clients per network, temperatures and Wi-Fi firmware crashes every 5 minutes.
- A hang triggers a reset by the watchdog (a hardware timer), and crash information survives the reset so it can be read back from stock.
- Each radio's own calibration is loaded at boot, the Bluetooth controller works with the stock firmware's address, and the status LED can be set to off, blue or white.
- `tc` can shape traffic on the NSS processor.

## Repository layout

| Path | Contents |
|---|---|
| `deploy.sh` | Builds and boots everything, step by step |
| `trees.sh`, `export.sh` | Create the source trees from the patch series, and export commits back to patches |
| `kernel/`, `backports/` | Upstream release address and our patches |
| `config-u6e.sh` | Kernel configuration |
| `nss/` | Builds the NSS drivers, the Wi-Fi stack and the NSS firmware download, with the patches for each |
| `fw/` | Builds the board data files; includes `ath11k-bdencoder` |
| `pkg/hostapd/` | hostapd build with our 19 patches |
| `pkg/iproute2-nss/` | `iproute2` with NSS support in `tc` |
| `mkrootfs.sh` | Creates the Debian root filesystem |
| `prep-rootfs.sh` | Adds the kernel, firmware and configuration, and produces one image per access point |
| `u6e-caldata` | Script that writes each radio's calibration at boot |
| `shim/` | The 32-bit to 64-bit boot shim |
| `boot/` | Staging and booting scripts, the Wi-Fi configuration generator (`wifi-up.sh`) and recovery tools |
| `test/` | Wi-Fi test tools |
| `site.conf.example` | Template for your site settings |

## Testing

`test/` checks the access points on the air, using a test client with a Wi-Fi card (set `TEST_CLIENT` in `site.conf`):

- `test/join.sh "<SSID>" [<BSSID>]` joins a network the way its kind requires, gets an address, pings the gateway and reports the association.
- `test/sniff.sh <MHz> <width> [<center MHz>] <seconds> <out.pcap>` captures radio traffic.
- `test/bip-verify.py <pcap> <BSSID> <key>` checks the beacon protection signature of every beacon in a capture.
- `U6E_AP=<ap> test/oce-retry.sh <interface> [<count>]` counts how many times a radio retries unanswered management frames (`mgmtsend.c` is its helper).

## Licence

The scripts are GPL-2.0-only (see `LICENSE`); patches keep their authors' licences. `fw/ath11k-bdencoder` is qca-swiss-army-knife's (ISC).

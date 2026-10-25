# Debian on the Ubiquiti UniFi U6 Enterprise

This repository turns a UniFi U6 Enterprise Wi-Fi access point into a small Debian 13 (trixie) computer running Linux 7.2.8, with all three radios working as a full-featured Wi-Fi 6/6E access point.

The U6 Enterprise has a Qualcomm IPQ5018 chip (two ARM cores, an internal 2.4 GHz radio), two QCN9074 radios for 5 GHz and 6 GHz, and one 2.5 GbE network port. Debian runs entirely from RAM, started next to the untouched stock firmware, so the stock system is always one reboot away. Qualcomm's NSS (a separate network processor inside the chip) does the packet forwarding in hardware, including for Wi-Fi.

The only thing ever written to the SPI flash (the small chip holding the boot loader) is the boot loader's settings, which hold the command that starts Debian (see [Booting](#booting)).

## What you need

- An x86 Linux build machine with the aarch64 cross compiler (and the armhf one, for the 32-bit boot shim), `mmdebstrap`, `qemu-user-static`, `u-boot-tools`, rustup, and exactly this cross toolchain (the agent and the controller are built through zig's C toolchain, and another version of any of it builds another binary):
  - Rust 1.97.1 with the `aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl` targets, pinned by `rust-toolchain.toml` (rustup installs it on the first `cargo` run in the checkout);
  - `zig` 0.17.0 (the official release tarball) and `cargo-zigbuild` 0.24.0 (`cargo install --locked cargo-zigbuild --version 0.24.0`), pinned by `toolchain.env`.

  `deploy.sh` checks all three versions before it builds the agent and stops on any other.
- Optionally, an Apple silicon Mac with OrbStack, reachable over SSH (`NATIVE_BUILD` in `site.conf`): the arm64 package and root filesystem builds then run there natively, many times faster than under `qemu-user-static`.
- SSH access to the stock firmware of each access point (the stock login set in `site.conf`).
- `site.conf`: your site's settings. Copy `site.conf.example` and fill it in; it is never committed. It holds:
  - the management network (VLAN, gateway, DNS, NTP, syslog collector) and the VLANs Wi-Fi clients land in;
  - the Wi-Fi plan: country, one line per SSID (name, kind, bands, default VLAN), channels, transmit power, and the optional 6 GHz Multiple BSSID setting;
  - how secrets are fetched: passphrases, the roaming key, the RADIUS-over-TLS certificate and the stock login are read by small shell functions, so they can come from a file or a password manager;
  - optionally, the controller `u6e-agent` streams to: its address and its public key (plain values), with each access point's own private key read by a shell function in that access point's block;
  - one block per access point (hostname, address, LED colour, Wi-Fi colours, and optionally its SSH host key, read by a shell function), and the test client for `test/`;
  - optionally, `AP_KNOWN_HOSTS`: the known_hosts file the boot tooling checks the access points' host keys against (see [Booting](#booting));
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
sudo BOOT=0 ./deploy.sh           # build everything, each image included, but boot nothing yet
sudo FORCE=1 ./deploy.sh ap1      # boot ap1 again even though it already runs the current build
```

`deploy.sh` runs these steps in order and skips any whose inputs have not changed since the last run (it records them in `stamps/`; logs go to `log/`):

1. `trees.sh`: prepares the kernel and Wi-Fi driver sources (see [Sources and patches](#sources-and-patches)).
2. `fw/mk-board2.sh`: assembles the board data files for the radios.
3. `config-u6e.sh` and `make`: configures and builds the kernel.
4. `nss/build.sh`: builds the NSS drivers and the Wi-Fi stack, and fetches the NSS firmware.
5. `pkg/hostapd/build.sh`: builds hostapd (the program that runs the Wi-Fi networks) as a Debian package.
6. `pkg/iproute2-nss/build.sh`: builds Debian's `iproute2` with the NSS traffic-shaping options added to `tc`.
7. `pkg/netlogd/build.sh`: builds Debian's `systemd-netlogd`, which forwards the log, with a fix for its journal file rotation.
8. `mkrootfs.sh`: creates the Debian root filesystem.
9. `pkg/u6e-agent` (a member of the cargo workspace in `Cargo.toml`): builds the access point's resident agent (Rust, one static binary): the neighbor report exchange between access points, the management network check, the state line in the log, the collectors that read the access point's Wi-Fi state (nl80211, hostapd, sysfs, the kernel log) into snapshots and events and its clients' connections (ECM's connection table, through `/dev/ecm_state`) into per-client flows, and, when given a controller (`--controller`, `--key`, `--controller-key`), the link that streams them to it over post-quantum TLS with pinned keys and carries out its commands. It runs as its own user `u6e-agent`, with no capabilities and in a tight systemd sandbox: hostapd gives that user's group its control sockets, `u6e-nss` creates ECM's state device for that group (each open of it is a new dump, so the agent opens it itself, allowed by the unit's `DeviceAllow`), systemd opens the root-only files it reads (the NSS load in debugfs, its private key), and it asks for `u6e-arm`/`u6e-fallback` through files their path units watch, as it may start no unit itself.
10. For each access point whose running image was built from other inputs (the parts of this repository that go into an image, which `ap-image.sh` lists, with only the agent's dependencies of `Cargo.lock`; `$BLOBS`, `site.conf` or the source trees): `prep-rootfs.sh` builds its image, unless the image built last for that access point (recorded in `stamps/built-<ap>`) has these inputs and is still in `images/` (`ap-image.sh` makes this choice); `boot/stage.sh` boots that image, and `deploy.sh` waits until all three radios are up. An access point already running the current build is left alone; `FORCE=1` boots it anyway, with the image already built for the current inputs if there is one (delete `stamps/built-<ap>` to build a fresh one). With `BOOT=0` each image is built and kept but not booted, so the access points keep running until a later run boots that same image.

Every image is kept in `images/` with a `MANIFEST` (versions and checksums), so an earlier build can be booted again without rebuilding. The image itself carries its `images/` name and the same versions in `/etc/u6e-image`.

## Sources and patches

The kernel and the Wi-Fi drivers are stored here as a download address plus a series of patches, not as copies of the upstream code:

- `kernel/`: Linux 7.2.8 (`kernel/source`) and 126 patches (`kernel/patches`) for this board and for NSS.
- `backports/`: OpenWrt's backports of the Linux 7.2 wireless stack (`backports/source`) and 195 patches (`backports/patches`) adding NSS Wi-Fi offload and fixes.

`./trees.sh` downloads each release (checked against its checksum), applies the patches as git commits and produces the working trees `linux-7.2.8/` and `backports-7.2/`. The commit IDs come out the same every time. To change something, commit in a tree and run `./export.sh kernel` (or `backports`) to turn your new commits back into patch files. `trees.sh` refuses to overwrite a tree whose work has not been exported.

Patches keep their original authors. We are sending our patches to the upstream projects (the kernel and hostapd).

## Booting

Ubiquiti's boot loader (U-Boot) is 32-bit and only starts its own signed images, but it will start any 32-bit ARM kernel. `shim/` is a tiny 32-bit program (208 bytes) that asks the chip's TrustZone (its built-in secure firmware) to restart the processor in 64-bit mode at our kernel.

`boot/go8.sh` does the staging while the stock firmware is running. It copies the shim, the kernel, the device tree and the initial filesystem into stock's data partition on the eMMC (changing only the parts that differ), and writes a one-shot U-Boot boot command that loads them. The next reboot starts Debian. The reboot after that returns to stock, because the command removes itself as it runs. `boot/stage.sh` does the whole cycle for one access point, from either system, and `boot/apstate.sh` tells you which system is running.

Both systems answer SSH on the access point's address, each with its own host keys. An image never carries the root filesystem's keys, which every image built from it would share: with `ssh_host_key` in its block in `site.conf`, an access point's image carries that Ed25519 key, the same in every image of it; without it, the image makes new keys at every boot, as it lives in RAM. With `AP_KNOWN_HOSTS` set, the boot tooling checks every host key against that file, our image's under the alias `<AP_HOSTNAME>` and stock's under `<AP_HOSTNAME>-stock`, and refuses a key it does not hold; without it, it checks none.

Persistent mode: with `U6E_PERSIST=1` in `site.conf`, the image re-arms the boot command once the management network is reachable (`u6e-agent` checks it every minute and asks for `u6e-arm`), so reboots and power cuts come back into Debian. If the network never comes up, or is lost later, `u6e-fallback` removes the boot command and the access point returns to stock instead of looping. `u6e-arm disarm` does the same by hand. Each Debian boot in persistent mode writes the 64 KiB U-Boot settings area twice.

## What the access point does

Wi-Fi starts by itself on every boot (`u6e-wifi.service`), with nothing else on the network needed. The access point has no battery-backed clock, so Wi-Fi first waits up to 60 seconds for NTP: hostapd checks the RADIUS server's certificate against the time. `boot/wifi-up.sh` generates the configuration from `site.conf`, and can install a changed one on a running access point.

**Networks**
- Three kinds of SSID, each on the bands you choose: WPA3-Personal, WPA3-Enterprise, and WPA2-Personal with MAC-address authentication for old devices that can do nothing newer.
- Enterprise logins are checked by your RADIUS server over TLS ("RadSec") spoken directly by hostapd. RADIUS can also place each client in its own VLAN.
- Optional 6 GHz Multiple BSSID: all 6 GHz networks share one beacon.

**Roaming and client help**
- Fast roaming between radios and access points (802.11r).
- Roaming advice for clients (802.11k and 802.11v). The access points send each other lists of their networks every 10 seconds (`u6e-agent`, a single small process that changes hostapd's lists only when they differ), so clients are told about the others.
- Optimized Connectivity (OCE), Agile Multiband (MBO) and Wi-Fi QoS Management, which help clients pick the best band and mark their traffic correctly.
- Beacon protection on 5 GHz and 6 GHz, which stops forged beacons.
- Time-of-flight ranging for indoor location, 6 GHz discovery frames, and 6 GHz announcements on the 2.4 and 5 GHz beacons so clients find 6 GHz quickly.

**Speed**
- Packet forwarding, Wi-Fi offload and encryption run on the NSS processor.
- Multicast and broadcast (mDNS, SSDP, ARP, IPv6 neighbor discovery) reach every client, each as unicast at its own rate, and a client's broadcasts reach the other clients on its network; nothing is isolated, proxied or snooped, so AirPlay and HomeKit devices find each other.
- The usual Wi-Fi 4/5/6 speed features are enabled: beamforming, TWT and spatial reuse among them.

**Running it day to day**
- The whole system log goes to your syslog collector (the access point keeps logs only in RAM), the kernel log goes out over the network, and `u6e-agent` adds load, memory, clients per network, temperatures (the SoC's sensors and each radio's own) and Wi-Fi firmware crashes every 5 minutes.
- With `CONTROLLER` set in `site.conf`, `u6e-agent` also streams the access point's Wi-Fi state (radios, networks, clients, events) and its identity (`/etc/u6e-image`) to the controller over post-quantum TLS, each side pinning the other's key. A client's rate each way is that of its last frame, as nl80211 reports it, except that an HT/VHT/HE client's last such rate stands for up to a minute over the legacy rates of the management and control frames between its data frames. A radio stays in the stream once seen, reported down while it serves no network (its hostapd exited, say), so its outage shows as a radio down rather than as no radio. Each client's connections go too: their count, how many the NSS hardware forwards, their bytes and packets each way and the 6 largest, every minute, every 10 s while the controller asks for it, and every connection (up to 4096) on request. They come from ECM's connection table, so no packet is looked at on the access point's CPU; a connection between two of its clients counts for both. ECM writes each connection in brief for it (our patch `nss/patches/qca-nss-ecm/902`, 13 lines where the full record has 175, whose writing costs the access point about 0.4 ms of CPU per connection), and `u6e-agent --print-flows` prints the flows and what a read cost. The controller can also kick a client, block or unblock it on every network of the access point, and steer it to another network of its SSID (802.11v, with disassociation after about 10 s if it stays); the access point keeps blocks in RAM only, and the controller sends them again whenever it connects. The access point works the same without it.
- Each radio is named after its band, `radio24`, `radio5` and `radio6` (its wiphy, as `iw` and the agent show it), and its interface `wlan24`, `wlan5` or `wlan6`, by the device it sits on: the kernel numbers the radios in the order they probe, which can swap the two QCN9074s from one boot to the next, so a name derived from that number would carry another radio's history after a reboot.
- Each radio reports its temperature (`/sys/class/ieee80211/radio*/hwmon*/temp1_input`), and its firmware throttles transmission when it runs hot, in steps with hysteresis: the 5 and 6 GHz radios stop transmitting half of the time above 100 °C, 90 % above 105 °C and entirely above 110 °C (back down below 95, 100 and 105 °C); the 2.4 GHz radio does the same above 105, 110 and 115 °C.
- The radios' spectral scan (FFT samples of the channel, read through debugfs) is built in; nothing runs it yet.
- A hang triggers a reset by the watchdog (a hardware timer), and crash information survives the reset so it can be read back from stock.
- When a radio's firmware crashes, the driver restarts it, and the access point keeps the latest firmware crash dump in `/var/lib/u6e-coredump/` (compressed: about 4 MB for a 5 or 6 GHz radio, 12 MB for the 2.4 GHz one, whose dump holds the whole WCSS region and the M3 dump area its firmware fills; readable by root only) and logs its name.
- Each radio's own calibration is loaded at boot, and the status LED can be set to off, blue or white.
- Bluetooth (LE and Classic) works with BlueZ under the stock firmware's address, the board's base MAC + 4: the controller stays unconfigured until `u6e-btaddr` gives it that address at boot. With `BT_POWERED=0` in `site.conf` it stays off until powered by hand (`bluetoothctl power on`). Never unload `btqcomipc` on a running access point: the SoC hangs until the watchdog resets it.
- `tc` can shape traffic on the NSS processor.

## Repository layout

| Path | Contents |
|---|---|
| `deploy.sh` | Builds and boots everything, step by step |
| `rust-toolchain.toml`, `toolchain.env` | The pinned build toolchain: Rust, and zig with cargo-zigbuild |
| `ap-image.sh` | The key of what this repository puts into an image, and the choice of the image `deploy.sh` boots on an access point: the one already built for the current inputs, or a new one |
| `trees.sh`, `export.sh` | Create the source trees from the patch series, and export commits back to patches |
| `kernel/`, `backports/` | Upstream release address and our patches |
| `config-u6e.sh` | Kernel configuration |
| `nss/` | Builds the NSS drivers, the Wi-Fi stack and the NSS firmware download, with the patches for each |
| `fw/` | Builds the board data files; includes `ath11k-bdencoder` |
| `pkg/hostapd/` | hostapd build with our 29 patches |
| `pkg/iproute2-nss/` | `iproute2` with NSS support in `tc` |
| `pkg/netlogd/` | `systemd-netlogd` (the log forwarder) without a spurious error at each journal file rotation |
| `pkg/u6e-proto/` | The wire protocol between the agent and the controller: messages (snapshots and their deltas, events, per-client flows, and the closed set of operator commands, kick, block, unblock and steer, each answered by a result), delta coding, framing, the frozen version frame each end sends first (`PROTOCOL`, bumped with every incompatible change to the messages, which a golden test of their encoding enforces), the strict MAC and hex parsing both ends share, and the TLS 1.3 configuration (X25519MLKEM768, pinned Ed25519 raw public keys, no session resumption) (Rust) |
| `pkg/u6e-controller/` | The Wi-Fi controller: the agents' sessions over the pinned-key TLS link (an agent of another protocol is turned away, logged once and shown as a protocol mismatch in the metrics and the UI), the live state of every access point, Prometheus metrics, and the web UI embedded in the binary (`ui/`: devices, clients, a client's session, events), kept live over a WebSocket; `cargo run -p u6e-controller --example replay` serves it fed by two simulated access points (Rust, hand-written JavaScript and CSS) |
| `pkg/u6e-agent/` | The access point's resident agent: neighbor reports across access points, management network check, state line, Wi-Fi state collectors and events, per-client flows from ECM's connection table, the telemetry link to the controller (which speaks only to a controller of its protocol and redials one that ends its sessions before saying anything ever more slowly, up to every 30 s), and the controller's commands through hostapd's control sockets: kick, block and unblock (every network's deny list, held in RAM and put back after a Wi-Fi restart), and steer (an 802.11v request naming the target from the 802.11k exchange), each checked before hostapd is asked anything (Rust) |
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

`test/ap-image.sh` needs no access point: it checks offline, with a stub `prep-rootfs.sh`, which image `ap-image.sh` picks (an image built with `BOOT=0` is the one booted next; changed inputs or a deleted image mean a new build; `FORCE=1` reuses the kept image; a failed build stops `deploy.sh` and records nothing), and, over commits to a scratch clone, that only a change to what goes into an image changes its key (a README, test, controller or controller-only dependency change does not; an agent source, agent dependency or `prep-rootfs.sh` change does).

## Licence

The scripts are GPL-2.0-only (see `LICENSE`); patches keep their authors' licences. `fw/ath11k-bdencoder` is qca-swiss-army-knife's (ISC).

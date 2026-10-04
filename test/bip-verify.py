#!/usr/bin/env python3
"""Check the beacon protection MIC of a BSS's beacons in a capture.

    test/bip-verify.py <pcap> <BSSID> <BIGTK hex>

BIP-CMAC-128 as IEEE Std 802.11-2024 12.5.3 (and hostapd's wlantest) computes
it: AES-128-CMAC over the AAD (Frame Control with Retry, Power Management and
More Data masked, then A1, A2, A3) and the frame body with the Timestamp and
the MME's MIC zeroed; the MIC is the first 8 octets. The BIGTK comes from
KEYS=1 test/join.sh.
"""
import json
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

WLAN_EID_MMIE = 76


def beacons(pcap, bssid):
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y",
         f"wlan.fc.type_subtype == 8 && wlan.bssid == {bssid} && "
         "radiotap.flags.badfcs == 0", "-T", "json", "-x"],
        capture_output=True, text=True, check=True).stdout
    for frame in json.loads(out or "[]"):
        raw = bytes.fromhex(frame["_source"]["layers"]["frame_raw"][0])
        radiotap_len = raw[2] | raw[3] << 8
        yield raw[radiotap_len:-4]  # without the FCS


def main():
    pcap, bssid, key = sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3])
    total = valid = 0
    for mpdu in beacons(pcap, bssid):
        hdr, body = mpdu[:24], bytearray(mpdu[24:])
        if len(body) < 18 or body[-18] != WLAN_EID_MMIE:
            print("beacon without an MME")
            continue
        mic = bytes(body[-8:])
        aad = bytes([hdr[0], hdr[1] & ~0x38 & 0xff]) + hdr[4:22]
        body[:8] = bytes(8)
        body[-8:] = bytes(8)
        cmac = CMAC(algorithms.AES(key))
        cmac.update(aad + bytes(body))
        total += 1
        valid += cmac.finalize()[:8] == mic
    print(f"{bssid}: {valid} of {total} beacon MICs verify")
    sys.exit(0 if total and valid == total else 1)


if __name__ == "__main__":
    main()

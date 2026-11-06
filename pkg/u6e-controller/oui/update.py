#!/usr/bin/env python3
"""Vendors the MAC vendor table the controller compiles in (manuf.tsv, read
by build.rs): Wireshark's compilation of the IEEE registry's MA-L, MA-M and
MA-S listings (epan/manuf-data.c, GPL-2.0-or-later), at the commit pinned
here and checked against its sha256, as one `<prefix>\t<organization>` line
per assigned block, the prefix 6, 7 or 9 hex digits.

    python3 pkg/u6e-controller/oui/update.py

To refresh it, pin a newer commit of epan/manuf-data.c and its sha256, run
this, and commit both files; the build itself never downloads anything.
"""
import hashlib
import pathlib
import re
import urllib.request

COMMIT = "9aa18f64694c422e7dbb86bc7bea4f0e8f20170f"
SHA256 = "9d47ad8dad8be799f3782ebc9b7c509b4a42dbb46fab459cdc3f720759871d9a"
URL = f"https://gitlab.com/wireshark/wireshark/-/raw/{COMMIT}/epan/manuf-data.c"
OUT = pathlib.Path(__file__).with_name("manuf.tsv")

# Each table's name and the hex digits of its prefixes.
TABLES = {"global_manuf_oui24_table": 6, "global_manuf_oui28_table": 7, "global_manuf_oui36_table": 9}
ROW = re.compile(r'\{ \{ ((?:0x[0-9A-F]{2}, )*0x[0-9A-F]{2}) \}, "(?:[^"\\]|\\.)*",\s*"((?:[^"\\]|\\.)*)" \}')


def main():
    data = urllib.request.urlopen(URL, timeout=60).read()
    got = hashlib.sha256(data).hexdigest()
    if got != SHA256:
        raise SystemExit(f"{URL}: sha256 {got}, pinned {SHA256}")
    text = data.decode("utf-8")
    rows = []
    for table, digits in TABLES.items():
        body = text[text.index(f"{table}[] = {{"):]
        body = body[: body.index("\n};")]
        for octets, name in ROW.findall(body):
            prefix = "".join(o[2:] for o in octets.split(", "))[:digits]
            name = name.replace('\\"', '"').replace("\\\\", "\\")
            rows.append(f"{prefix}\t{name}")
    header = f"# Wireshark epan/manuf-data.c at {COMMIT} (GPL-2.0-or-later), from the IEEE registry\n"
    OUT.write_text(header + "\n".join(sorted(rows)) + "\n")
    print(f"{OUT}: {len(rows)} blocks")


if __name__ == "__main__":
    main()

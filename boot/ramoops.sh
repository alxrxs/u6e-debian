#!/bin/bash
# Read our kernel's pstore (ramoops @ 0x4e000000, see the board DTS) from the
# stock firmware after a failed boot fell back to it: prints the console log,
# any oops/panic records and the pmsg journal u6e-netcheck leaves. memdump is
# built from memdump.c (static armhf; /dev/mem read() refuses the no-map range,
# mmap works) and lives in stock's /tmp.
#   ramoops.sh [lines]   (console tail length, default 60)
set -euo pipefail
. "$(dirname "$0")/lib.sh"
here=$(cd "$(dirname "$0")" && pwd)
ADDR=4e000000 SIZE=0x100000
[ "$here/memdump" -nt "$here/memdump.c" ] ||
	arm-linux-gnueabihf-gcc -static -O2 -o "$here/memdump" "$here/memdump.c"
raw=$U6E_TMP/ramoops
t0=$(date +%s)
until T=8 ap_stock -n true 2>/dev/null; do
	[ $(($(date +%s) - t0)) -lt 300 ] ||
		{ echo "ramoops.sh: stock firmware not reachable at $AP (still running our kernel? power-cycle)" >&2; exit 1; }
	sleep 3
done
T=120 ap_stock 'cat > /tmp/memdump && chmod 755 /tmp/memdump' < "$here/memdump"
T=120 ap_stock "/tmp/memdump $ADDR $SIZE" < /dev/null > "$raw"
python3 - "$raw" "${1:-60}" <<'PY'
import struct, sys, zlib
b = open(sys.argv[1], 'rb').read()
# Zones at their fixed offsets as the DTS sizes them (3 x 128K dump records,
# 512K console, 128K pmsg). Each header is sig/start/size, but something after
# the reboot overwrites the signature word, so trust only a sane start/size.
for off, cap, kind in ((0x0, 0x20000, 'crash record'), (0x20000, 0x20000, 'crash record'),
                       (0x40000, 0x20000, 'crash record'), (0x60000, 0x80000, 'console'),
                       (0xe0000, 0x20000, 'pmsg')):
    start, size = struct.unpack_from('<II', b, off + 4)
    if not 0 < size <= cap - 12 or start > size:
        continue
    data = b[off + 12:off + 12 + size]
    print(f'---- {kind} @+{off:#x} ({size} bytes)')
    if kind == 'console':
        log = data[start:] + data[:start] if start < size else data
        print('\n'.join(log.decode('utf-8', 'replace').splitlines()[-int(sys.argv[2]):]))
    elif kind == 'pmsg':  # u6e-netcheck's snapshot leads, the journal tail follows
        print(data.decode('utf-8', 'replace'))
    else:  # pstore deflates oops dumps (CONFIG_PSTORE_COMPRESS); ramoops prefixes a ====sec.nsec-C line
        if data.startswith(b'===='):
            data = data[data.index(b'\n') + 1:]
        try:
            data = zlib.decompress(data, -15)
        except zlib.error:
            pass
        print(data.decode('utf-8', 'replace')[-12000:])
PY

#!/bin/bash
# One boot cycle of a Debian image on the U6-Enterprise (no serial console). Each payload
# is a file in stock's /tmp/log (ext4 on the eMMC; stock refuses raw writes to
# mmcblk0) that is kept between cycles, and only the 64 KiB chunks that differ
# are rewritten in place: a rebuilt initrd (packed reproducibly, volatile files
# last) usually differs only in its tail. The file's extents become U-Boot
# reads. One fw_setenv batch (a single write of the 64 KiB SPI-NOR env) then
# arms a bootcmd_real that disarms itself (U-Boot's only saveenv), reads the
# payloads, CRC-gates them and bootz's the first one.
# Usage: go8.sh <zImage> <dtb-with-initrd-props> <initrd> [<arm64 Image>]
#   armv7: the zImage is the kernel. arm64: the zImage is shim/shim.bin, which
#   has the TZ monitor enter the Image (loaded at KERNEL64_ADDR) in AArch64.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
ZIMG_ADDR=0x44000000   # 128M window 0x40000000: AUTO_ZRELADDR -> kernel at 0x40008000
DTB_ADDR=0x47f00000
INITRD_ADDR=0x52200000 # must match linux,initrd-start in the DTB
KERNEL64_ADDR=0x41000000 # must match the shim's KERNEL_ENTRY
CRC_SCRATCH=0x4f000000
CHUNK=65536 # compare/write granularity: a DTB or script edit rewrites 64 KiB, not more
STAGE=/tmp/log/.u6e
here=$(cd "$(dirname "$0")" && pwd)
work=$U6E_TMP
ap() { ap_stock "$@"; }
staged_hashes() { # <name> <chunks>: sha256 of each chunk of the staged file
	ap -n "for i in \$(seq 0 $(($2 - 1))); do dd if=$STAGE/$1 bs=$CHUNK skip=\$i count=1 2>/dev/null | sha256sum | cut -c1-64; done"
}

stage() { # <name> <file>: rewrite the chunks that differ, verify, map the extents
	local n=$1 f=$2 size chunks i s len written=0 ino
	size=$(stat -c %s "$f"); chunks=$(((size + CHUNK - 1) / CHUNK))
	cp "$f" "$work/$n"; truncate -s $((chunks * CHUNK)) "$work/$n"
	mapfile -t want < <(python3 -c 'import hashlib, sys
d = open(sys.argv[1], "rb").read(); c = int(sys.argv[2])
for o in range(0, len(d), c): print(hashlib.sha256(d[o:o + c]).hexdigest())' "$work/$n" $CHUNK)
	ap -n "mkdir -p $STAGE"
	mapfile -t have < <(staged_hashes "$n" "$chunks")
	i=0
	while ((i < chunks)); do
		[ "${want[i]}" = "${have[i]:-}" ] && { i=$((i + 1)); continue; }
		s=$i; while ((i < chunks && i - s < 256)) && [ "${want[i]}" != "${have[i]:-}" ]; do i=$((i + 1)); done
		len=$((i - s))
		# Through RAM (/tmp is rootfs on stock): dd from a pipe would count short reads as blocks.
		dd if="$work/$n" bs=$CHUNK skip="$s" count="$len" 2>/dev/null |
			T=300 ap "cat > /tmp/u6e-chunk && dd if=/tmp/u6e-chunk of=$STAGE/$n bs=$CHUNK seek=$s conv=notrunc,fsync 2>/dev/null; rc=\$?; rm -f /tmp/u6e-chunk; exit \$rc"
		written=$((written + len))
	done
	# Cut a longer earlier payload back: U-Boot reads every extent.
	ap -n "dd if=/dev/null of=$STAGE/$n bs=$CHUNK seek=$chunks 2>/dev/null && sync"
	mapfile -t have < <(staged_hashes "$n" "$chunks")
	[ "${want[*]}" = "${have[*]}" ] || { echo "$n: verify failed"; exit 1; }
	ino=$(ap -n "ls -i $STAGE/$n" | awk '{print $1}')
	T=300 python3 "$here/ext4map.py" "$ino" > "$work/map_$n"
	echo "$n: $((written * CHUNK / 1024)) of $((chunks * CHUNK / 1024)) KiB written, $(grep -c ^EXT "$work/map_$n") extent(s)"
}
stage u6e.zimg "$1"; stage u6e.dtb "$2"; stage u6e.initrd "$3"
[ -n "${4:-}" ] && stage u6e.k64 "$4"

python3 - "$work" "$1" "$2" "$3" "${4:-}" "$ZIMG_ADDR" "$DTB_ADDR" "$INITRD_ADDR" "$KERNEL64_ADDR" "$CRC_SCRATCH" <<'PY'
import os, sys, zlib
work, zimg, dtb, initrd, k64 = sys.argv[1:6]
za, da, ia, ka, scratch = (int(x, 16) for x in sys.argv[6:11])
out = f'{work}/env'
def load(name, path, base, slot):
    # Each extent to consecutive RAM, then a CRC of the file's own length.
    cmds, addr = [], base
    for l in open(f'{work}/map_{name}'):
        if l.startswith('EXT'):
            p = dict(x.split('=') for x in l.split()[1:])
            cmds.append(f'mmc read {addr:#x} {int(p["disk_sector"]):#x} {int(p["sectors"]):#x};')
            addr += int(p['sectors']) * 512
    size = os.path.getsize(path)
    crc = zlib.crc32(open(path, 'rb').read())
    # crc32 stores big-endian; itest reads the slot as a native (LE) long.
    want = int.from_bytes(crc.to_bytes(4, 'big'), 'little')
    return ' '.join(cmds) + f' crc32 {base:#x} {size:#x} {slot:#x}', f'itest *{slot:#x} == {want:#x}'
parts = [load('u6e.zimg', zimg, za, scratch), load('u6e.dtb', dtb, da, scratch + 0x10),
         load('u6e.initrd', initrd, ia, scratch + 0x20)]
if k64:
    parts.append(load('u6e.k64', k64, ka, scratch + 0x30))
env = {f'u8{i}': cmd for i, (cmd, _) in enumerate(parts)}
gates = [g for _, g in parts]
env['u8b'] = ''.join(f'if {g}; then ' for g in gates) + f'bootz {za:#x} - {da:#x}; ' + 'fi; ' * len(gates) + 'bootubnt'
env['bootcmd_real'] = 'setenv bootcmd_real bootubnt; saveenv; ' + ''.join(f'run u8{i}; ' for i in range(len(parts))) + 'run u8b'
# Names the earlier staging schemes left behind: a bare name deletes it.
stale = 'z8r0 z8r1 z8r2 z8r3 z8crc d8r0 d8r1 d8crc i8r0 i8r1 i8r2 i8r3 i8r4 i8r5 i8crc k8r0 k8r1 k8r2 k8r3 k8crc u8z u8d u8i u8k c8go c8ret'
with open(out, 'w') as f:
    for k in stale.split():
        if k not in env:
            f.write(f'{k}\n')
    for k, v in env.items():
        assert len(v) < 1000, f'{k} too long ({len(v)})'
        f.write(f'{k} {v}\n')
print(open(out).read())
PY

# One env write arms the whole cycle.
ap "fw_setenv -s -" < "$work/env"
ap -n 'fw_printenv bootcmd_real'

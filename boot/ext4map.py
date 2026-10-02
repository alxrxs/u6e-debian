# ext4map.py <inode>: the eMMC sectors of a file on stock's /tmp/log (ext4 on
# mmcblk0p5), read over SSH from the stock firmware; go8.sh turns them into
# U-Boot "mmc read" commands. Needs APPW and U6E_STOCK from boot/lib.sh.
import os
import struct
import subprocess
import sys
AP = ['sshpass', '-f', os.environ['APPW'], 'ssh', '-n', '-o', 'StrictHostKeyChecking=no',
      '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'PubkeyAuthentication=no',
      os.environ['U6E_STOCK']]
def rd(dev, off, n):
    bs = 512; skip = off // bs; cnt = (off + n + bs - 1) // bs - skip
    out = subprocess.run(AP + [f'dd if={dev} bs={bs} skip={skip} count={cnt} 2>/dev/null'], capture_output=True, check=True).stdout
    s = off - skip * bs
    return out[s:s + n]
P = '/dev/mmcblk0p5'
part_start = int(subprocess.run(AP + ['cat /sys/block/mmcblk0/mmcblk0p5/start'], capture_output=True).stdout)
sb = rd(P, 1024, 1024)
assert struct.unpack_from('<H', sb, 0x38)[0] == 0xEF53, 'not ext4'
bsz = 1024 << struct.unpack_from('<I', sb, 24)[0]
ipg = struct.unpack_from('<I', sb, 40)[0]; isz = struct.unpack_from('<H', sb, 88)[0]
fdb = struct.unpack_from('<I', sb, 20)[0]; incompat = struct.unpack_from('<I', sb, 96)[0]
is64 = bool(incompat & 0x80); dsz = struct.unpack_from('<H', sb, 254)[0] if is64 else 32
ino = int(sys.argv[1]); g, idx = divmod(ino - 1, ipg)
gd = rd(P, (fdb + 1) * bsz + g * dsz, dsz)
itab = struct.unpack_from('<I', gd, 8)[0] | ((struct.unpack_from('<I', gd, 0x28)[0] << 32) if is64 and dsz >= 64 else 0)
inode = rd(P, itab * bsz + idx * isz, isz)
size = struct.unpack_from('<I', inode, 4)[0] | (struct.unpack_from('<I', inode, 0x6C)[0] << 32)
assert struct.unpack_from('<I', inode, 0x20)[0] & 0x80000, 'not extent-mapped'
def walk(node):
    magic, n, _, depth = struct.unpack_from('<HHHH', node, 0); assert magic == 0xF30A
    out = []
    for i in range(n):
        e = node[12 + 12*i: 24 + 12*i]
        if depth == 0:
            lblk, ln, hi, lo = struct.unpack('<IHHI', e)
            assert ln <= 32768, 'unwritten extent'
            out.append((lblk, (hi << 32) | lo, ln))
        else:
            lblk, lo, hi, _ = struct.unpack('<IIHH', e)
            out += walk(rd(P, ((hi << 32) | lo) * bsz, bsz))
    return out
ext = sorted(walk(inode[0x28:0x28+60]))
print(f"size={size} blocksize={bsz} inode={ino} extents={len(ext)}")
exp = 0
for lblk, pblk, ln in ext:
    assert lblk == exp, 'hole in file'; exp += ln
    print(f"EXT logical={lblk} phys_block={pblk} blocks={ln} disk_sector={part_start + pblk*bsz//512} sectors={ln*bsz//512}")

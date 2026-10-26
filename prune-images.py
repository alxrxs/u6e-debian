#!/usr/bin/env python3
"""Prune the kept images: in <images>/ (deploy.sh's images/), remove every
image but those named by --keep (each access point's current image, its
way back, the build of the pinned inputs) and the newest --newest of each
access point (by name, which starts with the build time). An image is a
directory whose MANIFEST names its access point (`ap:`); anything else is
left alone. Run as root, it trusts nothing about the directory's shape:
every directory and file is opened without following a link, a MANIFEST is
read only as a regular file, an image with anything but regular files in
it is left alone, and each removal goes through a descriptor of the
directory it is in, so a link swapped in meanwhile leads nowhere.
  python3 -I prune-images.py <images> [--newest N] [--keep <id>]... [--dry-run]
"""
import argparse
import os
import stat
import sys

MANIFEST_MAX = 64 * 1024
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def manifest_ap(image_fd):
    """The access point an image's MANIFEST names; None when it names none."""
    try:
        fd = os.open("MANIFEST", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=image_fd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MANIFEST_MAX:
            return None
        text = os.read(fd, MANIFEST_MAX).decode(errors="replace")
    finally:
        os.close(fd)
    for line in text.splitlines():
        if line.startswith("ap:"):
            words = line[3:].split()
            return words[0] if words else None
    return None


def images(dir_fd):
    """Each image in the directory: its name and its access point."""
    found = []
    for name in sorted(os.listdir(dir_fd)):
        try:
            fd = os.open(name, DIR, dir_fd=dir_fd)
        except OSError:
            continue
        try:
            ap = manifest_ap(fd)
        finally:
            os.close(fd)
        if ap:
            found.append((name, ap))
    return found


def remove(dir_fd, name):
    """Removes image `name` and the regular files in it; False when it holds
    anything else, and is left as it is."""
    fd = os.open(name, DIR, dir_fd=dir_fd)
    try:
        entries = os.listdir(fd)
        for entry in entries:
            st = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                return False
        for entry in entries:
            os.unlink(entry, dir_fd=fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=dir_fd)
    return True


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("images")
    p.add_argument("--newest", type=int, default=3)
    p.add_argument("--keep", action="append", default=[])
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    dir_fd = os.open(a.images, DIR)
    found = images(dir_fd)
    keep = set(a.keep)
    by_ap = {}
    for name, ap in found:
        by_ap.setdefault(ap, []).append(name)
    for names in by_ap.values():
        keep.update(sorted(names)[-a.newest:] if a.newest > 0 else [])
    pruned = 0
    for name, ap in found:
        if name in keep:
            continue
        if a.dry_run:
            print(f"would prune {name} ({ap})")
            pruned += 1
        elif remove(dir_fd, name):
            print(f"pruned {name} ({ap})")
            pruned += 1
        else:
            print(f"left {name} ({ap}): it holds more than files", file=sys.stderr)
    kept = len(found) - pruned
    print(f"{'would keep' if a.dry_run else 'kept'} {kept} of {len(found)} images")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Prune the kept images of the u6e-debian tree <tree> (deploy.sh's
images/) by its retention rule: keep each access point's running image
(stamps/running-<ap>), its image of the current inputs (stamps/built-<ap>),
those named by --keep (the deploy runner's, which ap-image.sh's
prune_images asks it for) and the newest --newest (3) of each access point
(by name, which starts with the build time); prune nothing while what an
access point named by --ap runs is not known (its stamps/ap-<ap> names other
inputs than its built image and no running image is recorded). An image is a
directory whose MANIFEST names its access point (`ap:`); anything else,
names starting with a dot included, is left alone.

Run as root on a tree another user can write, it trusts nothing about its
shape: every directory and file is opened through a descriptor of the one it
is in, never following a link and never waiting on a FIFO, a stamp or a
MANIFEST is read only as a small regular file, an image is first renamed to
`.<id>.pruning` (so nothing takes it for a kept image any more) and then
emptied of its regular files and removed, one that holds anything else is
left, and an error on one image skips that image, said, never the run.
Leftover `.<id>.pruning` directories of an interrupted run go first. Use it
through ap-image.sh's prune_images (or prune.sh), which passes the runner's
keeps: run alone it knows only the stamps.
  python3 -I prune-images.py <tree> --ap <ap>... [--keep <id>]... [--newest N] [--dry-run]
"""
import argparse
import os
import stat
import sys

SMALL = 64 * 1024
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
PRUNING = ".pruning"


def say(*what):
    print(*what, file=sys.stderr)


def read_small(dir_fd, name):
    """The text of regular file `name` in the directory, at most SMALL bytes;
    None when it is missing, not a regular file, too long or unreadable."""
    try:
        fd = os.open(name, FILE, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > SMALL:
            say(f"{name}: not a small regular file; taken as missing")
            return None
        return os.read(fd, SMALL).decode(errors="replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def manifest_ap(image_fd):
    """The access point an image's MANIFEST names; None when it names none."""
    text = read_small(image_fd, "MANIFEST") or ""
    for line in text.splitlines():
        if line.startswith("ap:"):
            words = line[3:].split()
            return words[0] if words else None
    return None


def images(dir_fd):
    """Each image in the directory: its name and its access point."""
    found = []
    for name in sorted(os.listdir(dir_fd)):
        if name.startswith("."):
            continue
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


def empty(dir_fd, name):
    """Removes directory `name` and the regular files in it; False when it
    holds anything else, when it is left as it is."""
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


def remove(dir_fd, name):
    """Prunes image `name`: renamed out of the kept images' names at once,
    then emptied; a message when it could not be."""
    aside = f".{name}{PRUNING}"
    try:
        os.rename(name, aside, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        if not empty(dir_fd, aside):
            return f"{aside}: it holds more than files; left"
    except OSError as e:
        return f"{name}: {e}; left"
    return None


def stamps(tree_fd, aps):
    """The images the stamps name (built and running), and the access points
    whose running image is not known."""
    try:
        fd = os.open("stamps", DIR, dir_fd=tree_fd)
    except OSError:
        return set(), []
    keep, unknown = set(), []
    try:
        for ap in aps:
            built = (read_small(fd, f"built-{ap}") or "").strip()
            running = (read_small(fd, f"running-{ap}") or "").strip()
            if built:
                keep.add(built.rsplit("/", 1)[-1])
            if running:
                keep.add(running)
                continue
            booted = (read_small(fd, f"ap-{ap}") or "").strip()
            if booted and booted != built.split(" ", 1)[0]:
                unknown.append(ap)
    finally:
        os.close(fd)
    return keep, unknown


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("tree")
    p.add_argument("--ap", action="append", required=True)
    p.add_argument("--newest", type=int, default=3)
    p.add_argument("--keep", action="append", default=[])
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    try:
        tree_fd = os.open(a.tree, DIR)
        dir_fd = os.open("images", DIR, dir_fd=tree_fd)
    except OSError as e:
        say(f"images: {a.tree}: {e}; none pruned")
        return
    keep, unknown = stamps(tree_fd, a.ap)
    if unknown:
        print(f"images: what {' '.join(unknown)} runs is not known (no stamps/running-<ap>); none pruned")
        return
    if not a.dry_run:
        for name in os.listdir(dir_fd):
            if name.startswith(".") and name.endswith(PRUNING):
                try:
                    if not empty(dir_fd, name):
                        say(f"{name}: it holds more than files; left")
                except OSError as e:
                    say(f"{name}: {e}; left")
    found = images(dir_fd)
    keep.update(a.keep)
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
            continue
        why = remove(dir_fd, name)
        if why:
            say(why)
        else:
            print(f"pruned {name} ({ap})")
            pruned += 1
    kept = len(found) - pruned
    print(f"{'would keep' if a.dry_run else 'kept'} {kept} of {len(found)} images")


if __name__ == "__main__":
    main()

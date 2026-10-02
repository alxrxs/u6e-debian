#!/bin/bash
# Import files an OpenWrt target carries as a files/ overlay into the current
# kernel tree as one commit, credited to whoever first added the first file in
# that repo, with the source named in the message.
# Usage (in a kernel tree): import-overlay.sh <files dir in a git repo> <path>...
#   e.g. import-overlay.sh ~/nss-build/openwrt-ipq/target/linux/qualcommax/files net/core/skbuff_recycle.c ...
set -euo pipefail
src=$(readlink -f "$1"); shift
repo=$(git -C "$src" rev-parse --show-toplevel)
rel=${src#"$repo"/}
add=$(git -C "$repo" log --diff-filter=A --format=%h -- "$rel/$1" | tail -1)
for f in "$@"; do install -D -m0644 "$src/$f" "$f"; done
git add -- "$@"
names=$(for f in "$@"; do basename "$f"; done | paste -sd, - | sed 's/,/, /g')
{ echo "Import $names"; echo
  echo "From $(git -C "$repo" remote get-url origin) $rel/ at $(git -C "$repo" rev-parse --short HEAD); first added in $add (\"$(git -C "$repo" log -1 --format=%s "$add")\")."; } |
	git commit -q --author="$(git -C "$repo" log -1 --format='%an <%ae>' "$add")" -F -
git log -1 --format='%h %an | %s'

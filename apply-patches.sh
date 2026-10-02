#!/bin/bash
# Apply patch files onto the current branch, one commit each, keeping the
# original author: git am when the patch is an mbox, else patch -p1 + patch_meta.
# Usage (in a kernel tree): apply-patches.sh <patch>...
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/patch-meta.sh"
for p in "$@"; do
	if git am -q --3way "$p" 2>/dev/null; then echo "am    $(basename "$p")"; continue; fi
	git am --abort 2>/dev/null || true
	t=$(mktemp -d)
	patch_meta "$p" "$t"
	patch -p1 -F0 -s -f --no-backup-if-mismatch < "$p"
	git add -A
	{ cat "$t/subject"; echo; cat "$t/msg"; } | git commit -q --author="$(cat "$t/author")" -F -
	rm -rf "$t"; echo "patch $(basename "$p")"
done

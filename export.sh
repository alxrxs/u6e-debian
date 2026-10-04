#!/bin/bash
# Turn the commits made in a source tree back into its patch series: every
# commit after the upstream release becomes <series>/patches/NNNN-*.patch
# (the old files are replaced), so the change can be committed here.
#   ./export.sh kernel|backports
set -euo pipefail
cd "$(dirname "$0")"
s=${1:?kernel or backports}
# shellcheck source=kernel/source
. "$s/source"
[ -z "$(git -C "$DIR" status --porcelain)" ] || { echo "$DIR has uncommitted changes" >&2; exit 1; }
base=$(git -C "$DIR" rev-list --max-parents=0 HEAD)
rm -f "$s"/patches/*.patch
git -C "$DIR" format-patch -q --zero-commit --no-signature -o "$PWD/$s/patches" "$base..HEAD"
git -C "$DIR" rev-parse HEAD > "$DIR/.git/u6e-head"
cat "$s/source" "$s"/patches/*.patch | sha256sum | cut -d' ' -f1 > "$DIR/.git/u6e-series"
echo "$s: $(find "$s/patches" -name '*.patch' | wc -l) patches; commit $s/patches"

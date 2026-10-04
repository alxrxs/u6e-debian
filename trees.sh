#!/bin/bash
# Build the two source trees the image is compiled from, linux-7.2.8/ and
# backports-7.2/: an upstream release (<series>/source names it and its sha256;
# the download is kept in dl/) with our patch series (<series>/patches) applied
# on top as git commits. Identities and dates are fixed, so a series always
# gives the same commit IDs. A tree is rebuilt only when its series changed,
# and never while it holds work not yet exported with export.sh.
#   ./trees.sh [kernel|backports]...    (default: both)
set -euo pipefail
cd "$(dirname "$0")"
export GIT_COMMITTER_NAME=u6e-debian GIT_COMMITTER_EMAIL=u6e-debian@localhost
mkdir -p dl
build() { # <series>
	local s=$1 key tarball tmp
	# shellcheck source=kernel/source
	. "$s/source"
	key=$(cat "$s/source" "$s"/patches/*.patch | sha256sum | cut -d' ' -f1)
	if [ -d "$DIR" ]; then
		[ "$(cat "$DIR/.git/u6e-series" 2>/dev/null)" != "$key" ] || { echo "$s: $DIR is current"; return; }
		if [ -n "$(git -C "$DIR" status --porcelain)" ] ||
			[ "$(git -C "$DIR" rev-parse HEAD)" != "$(cat "$DIR/.git/u6e-head" 2>/dev/null)" ]; then
			echo "$s: $DIR has work not exported (./export.sh $s); left alone" >&2
			return 1
		fi
		rm -rf "${PWD:?}/$DIR"
	fi
	tarball=dl/${URL##*/}
	if [ ! -f "$tarball" ]; then
		curl -fsSL -o "$tarball.part" "$URL"
		mv "$tarball.part" "$tarball"
	fi
	echo "$SHA256  $tarball" | sha256sum -c --quiet
	tmp=$(mktemp -d -p .)
	tar -xf "$tarball" -C "$tmp"
	mv "$tmp/$DIR" "$DIR"
	rmdir "$tmp"
	git -C "$DIR" init -q -b u6e
	git -C "$DIR" add --all
	GIT_COMMITTER_DATE=$BASE_DATE git -C "$DIR" commit -q --author="$BASE_AUTHOR" --date="$BASE_DATE" -m "$BASE_SUBJECT"
	git -C "$DIR" am -q --whitespace=nowarn --committer-date-is-author-date "$PWD/$s"/patches/*.patch
	git -C "$DIR" rev-parse HEAD > "$DIR/.git/u6e-head"
	echo "$key" > "$DIR/.git/u6e-series"
	echo "$s: $DIR built, $(git -C "$DIR" rev-list --count HEAD~0 --not "$(git -C "$DIR" rev-list --max-parents=0 HEAD)") patches on $BASE_SUBJECT"
}
[ $# -gt 0 ] || set -- kernel backports
for s in "$@"; do build "$s"; done

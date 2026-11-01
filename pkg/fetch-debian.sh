#!/bin/bash
# Fetch a Debian source package's files from snapshot.debian.org at a pinned
# time and check each one's sha256: deb.debian.org drops a version once a
# newer one replaces it, the snapshot keeps every file the archive had.
#   pkg/fetch-debian.sh <dir> <snapshot time> <pool dir> <sha256>=<file>...
# e.g. pkg/fetch-debian.sh work 20260216T203826Z main/w/wpa <sha256>=wpa_2.11-2.debian.tar.xz
set -euo pipefail
dir=$1 at=$2 pool=$3
shift 3
for f in "$@"; do
	sum=${f%%=*} name=${f#*=}
	curl -fsSL -o "$dir/$name" "https://snapshot.debian.org/archive/debian/$at/pool/$pool/$name"
	echo "$sum  $dir/$name" | sha256sum -c --quiet
done

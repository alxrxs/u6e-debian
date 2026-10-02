#!/bin/bash
# Commit the staged/working changes of a hand-ported patch under its original
# author and message, plus a note on what the port changed.
# Usage (in a kernel tree): commit-port.sh <original.patch> "<port note>" <path>...
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/patch-meta.sh"
p=$1 note=$2; shift 2
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
patch_meta "$p" "$t"
git add -- "$@"
who=$(git config user.name); who=${who%%[- ]*}
{ cat "$t/subject"; echo; cat "$t/msg"; echo "[$who: $note]"; } |
	git commit -q --author="$(cat "$t/author")" -F -
git log -1 --format='%h %an | %s'

#!/bin/bash
# Apply a patch list in order onto the current kernel tree, resuming where it
# left off. An entry counts as committed when its subject is in the log at
# least as often as the list has used it so far: OpenWrt's split series gives
# a subsys/ patch and its ath11k/ half one subject. Entries already in the base
# are reported UPSTREAM, a patch whose context drifted is placed hunk by hunk
# by unique text match (apply-unique.py), and the first hunk that cannot be
# placed stops the run for a hand port (commit-port.sh), after which re-run.
# Usage (in a kernel tree): apply-list.sh <list file> <patch dir>
set -euo pipefail
list=$1 dir=$2
here=$(dirname "$(readlink -f "$0")")
subject() { # what apply-patches.sh / git am will use as the commit subject
	local s
	s=$(git mailinfo /dev/null /dev/null < "$1" | sed -n 's/^Subject: //p')
	if [ -n "$s" ]; then echo "$s"; else basename "$(readlink -f "$1")" .patch | sed -E 's/^[0-9]+(-[0-9]+)?-//'; fi
}
done_subjects=$(git log --format=%s)
declare -A seen
while read -r f; do
	p=$dir/$f
	s=$(subject "$p"); seen[$s]=$((${seen[$s]:-0} + 1))
	(($(grep -cxF -- "$s" <<< "$done_subjects" || true) >= seen[$s])) && continue
	# Forward first: a patch that only deletes lines also reverse-applies cleanly.
	if ! patch -p1 -F0 --dry-run -s -f < "$p" >/dev/null 2>&1 && ! git apply --check -3 "$p" 2>/dev/null; then
		if patch -p1 -F0 -R --dry-run -s -f < "$p" >/dev/null 2>&1; then echo "UPSTREAM $f"; continue; fi
		# Context drifted: place each hunk by a unique text match, or stop.
		if report=$("$here/apply-unique.py" --check "$p"); then
			"$here/apply-unique.py" "$p" >/dev/null
			"$here/commit-port.sh" "$p" "Context drifted; hunks placed by unique match ($(grep -c '^trimmed' <<< "$report") with trimmed context)." .
			echo "unique   $f"; continue
		fi
		echo "STOP     $f"
		grep -A60 '^FAILED' <<< "$report" || true
		exit 1
	fi
	"$here/apply-patches.sh" "$p"
done < "$list"
echo "list complete: $(git rev-list --count HEAD) commits"

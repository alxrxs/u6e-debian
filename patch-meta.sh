# shellcheck shell=bash
# Sourced by apply-patches.sh and commit-port.sh.
# patch_meta <patch> <dir>: write <dir>/{subject,author,msg} for a patch. A
# patch with no mail header is credited to whoever added the file in its own
# git repo, and the message names that file and commit.
patch_meta() {
	local p=$1 t=$2 d r rel add
	git mailinfo "$t/msg" "$t/patch" < "$p" > "$t/info"
	sed -n 's/^Subject: //p' "$t/info" > "$t/subject"
	echo "$(sed -n 's/^Author: //p' "$t/info") <$(sed -n 's/^Email: //p' "$t/info")>" > "$t/author"
	if [ ! -s "$t/subject" ]; then
		d=$(dirname "$(readlink -f "$p")")
		r=$(git -C "$d" rev-parse --show-toplevel)
		rel=$(readlink -f "$p"); rel=${rel#"$r"/}
		add=$(git -C "$r" log --diff-filter=A -1 --format='%h' -- "$rel")
		git -C "$r" log -1 --format='%an <%ae>' "$add" > "$t/author"
		basename "$(readlink -f "$p")" .patch | sed -E 's/^[0-9]+(-[0-9]+)?-//' > "$t/subject"
		echo "Imported from $(git -C "$r" remote get-url origin) $rel (added in $add); the patch file carries no author or description." > "$t/msg"
	fi
}

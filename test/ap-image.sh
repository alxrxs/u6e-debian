#!/bin/bash
# Offline check of ap-image.sh: the choice deploy.sh makes per access point,
# build an image or boot the one kept for the same inputs, in a scratch
# directory with a stub prep-rootfs.sh that keeps numbered images; and the key
# of those inputs, over commits to a scratch clone of this repository.
#   test/ap-image.sh
set -u
repo=$(cd "$(dirname "$0")/.." && pwd)
lib=$repo/ap-image.sh
dir=$(mktemp -d) || exit 1
trap 'rm -rf -- "$dir"' EXIT
cd "$dir" || exit 1
mkdir stamps log
# shellcheck disable=SC2034 # ap_image's log directory, as in deploy.sh
L=$dir/log
cat > prep-rootfs.sh <<'EOF'
#!/bin/sh
[ -e fail-build ] && exit 1
n=$(($(cat builds 2>/dev/null || echo 0) + 1))
echo $n > builds
mkdir -p images/$n-$U6E_AP && touch images/$n-$U6E_AP/MANIFEST
echo "kept as images/$n-$U6E_AP"
EOF
chmod +x prep-rootfs.sh
# shellcheck disable=SC2317 # called by ap_image
fail() { echo "$*" >&2; exit 1; }
# shellcheck source=../ap-image.sh
. "$lib"

bad=0
# check <what> <expected IMAGE, or "skip"> <ap> <key>
check() {
	local what=$1 want=$2 got
	if ap_image "$3" "$4" > /dev/null; then got=$IMAGE; else got=skip; fi
	if [ "$got" = "$want" ]; then echo "ok:   $what"; else echo "FAIL: $what: got $got, want $want"; bad=1; fi
}
booted() { echo "$2" > "stamps/ap-$1"; }

check "a first run builds" images/1-ap1 ap1 k1
check "BOOT=0 then a plain run boots the image built ahead" images/1-ap1 ap1 k1
booted ap1 k1
check "an AP that runs these inputs is left alone" skip ap1 k1
FORCE=1 check "FORCE=1 boots the kept image again, no rebuild" images/1-ap1 ap1 k1
check "inputs changed since the build: a new image" images/2-ap1 ap1 k2
check "and that one is reused" images/2-ap1 ap1 k2
rm -rf images/2-ap1
check "a deleted kept image is built again" images/3-ap1 ap1 k2
FORCE=1 check "FORCE=1 with no kept image builds one" images/4-ap1 ap1 k3
check "each AP has its own image" images/5-ap2 ap2 k3
touch fail-build
if (ap_image ap1 k4 > /dev/null 2>&1); then echo "FAIL: a failed build stops deploy.sh"; bad=1; else echo "ok:   a failed build stops deploy.sh"; fi
if [ "$(cat stamps/built-ap1)" = "k3 images/4-ap1" ]; then echo "ok:   and records nothing"; else echo "FAIL: a failed build changed stamps/built-ap1"; bad=1; fi

git -c safe.directory='*' clone -q "$repo" clone && cd clone || exit 1
for p in "${IMAGE_PATHS[@]}"; do
	[ -e "$p" ] || { echo "FAIL: IMAGE_PATHS names $p, which does not exist"; bad=1; }
done
# key <what> <same|new> <file>...: commit the changed files; the key must stay
# or change.
key=$(image_tree)
key() {
	local what=$1 want=$2 got
	shift 2
	git -c user.name=test -c user.email=test@localhost commit -qm "$what" -- "$@" ||
		{ echo "FAIL: $what: nothing to commit"; bad=1; }
	got=$(image_tree) || { echo "FAIL: $what: no key"; bad=1; }
	if { [ "$want" = same ] && [ "$got" = "$key" ]; } || { [ "$want" = new ] && [ "$got" != "$key" ]; }; then
		echo "ok:   $what: $want key"
	else
		echo "FAIL: $what: want $want key, got $got after $key"; bad=1
	fi
	key=$got
}
echo >> README.md
key "a README change" same README.md
echo >> pkg/u6e-agent/tests/fixtures/status-wlan5.txt
key "an agent test fixture" same pkg/u6e-agent/tests/fixtures/status-wlan5.txt
echo >> pkg/u6e-controller/src/main.rs
key "a controller change" same pkg/u6e-controller/src/main.rs
# A crate only the controller depends on, as cargo would lock it.
sed -i '/^name = "u6e-controller"$/,/^dependencies = \[$/s/^dependencies = \[$/&\n "controller-only",/' Cargo.lock
printf '\n[[package]]\nname = "controller-only"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "%064d"\n' 0 >> Cargo.lock
grep -qx ' "controller-only",' Cargo.lock || { echo "FAIL: the controller does not depend on controller-only"; bad=1; }
key "a dependency of the controller alone" same Cargo.lock
sed -i '/^name = "libc"$/{n;s/^version = .*/version = "0.2.999"/}' Cargo.lock
key "a dependency of the agent" new Cargo.lock
echo >> pkg/u6e-agent/src/main.rs
key "an agent source change" new pkg/u6e-agent/src/main.rs
echo >> pkg/u6e-spectral/tests/fixtures/radio5-80mhz.relay
key "a spectrum helper test fixture" same pkg/u6e-spectral/tests/fixtures/radio5-80mhz.relay
echo >> pkg/u6e-spectral/src/main.rs
key "a spectrum helper source change" new pkg/u6e-spectral/src/main.rs
echo >> prep-rootfs.sh
key "a prep-rootfs.sh change" new prep-rootfs.sh
exit $bad

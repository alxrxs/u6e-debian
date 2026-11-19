#!/bin/bash
# Starts the image's u6e-shaper@ and u6e-capture@ units on this host, their
# sandboxes exactly as prep-rootfs.sh writes them, and checks that both of
# each one's commands ran: ExecStart (the helper's own complaint, as no agent
# talks to it) and ExecStopPost (its undo, which must end 0). A sandbox
# systemd cannot set up fails them before they run (226/NAMESPACE).
#   sudo test/helper-units.sh
# Needs root and systemd, and host builds of the helpers (cargo build -p
# u6e-shaper -p u6e-capture). Only what an AP has and a build host lacks is
# swapped: the helpers' binaries, the sockets' group, and ECM's /proc/sys
# files where ECM is not loaded, for files of the same kind (the helpers
# write none of them here). Everything it adds it removes.
set -u
repo=$(cd "$(dirname "$0")/.." && pwd)
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
bin=/var/lib/u6e-unit-test # exec-able and outside ProtectHome and PrivateTmp
units=/run/systemd/system
made=()
# shellcheck disable=SC2317 # the EXIT trap's
cleanup() {
	for h in shaper capture; do
		systemctl stop "u6e-unit-test-$h.socket" 2> /dev/null
		systemctl reset-failed "u6e-unit-test-$h@*" "u6e-unit-test-$h.socket" 2> /dev/null
		rm -f "$units/u6e-unit-test-$h.socket" "$units/u6e-unit-test-$h@.service"
	done
	systemctl daemon-reload
	rm -rf -- "$bin" "${made[@]}"
}
trap cleanup EXIT

mkdir -p "$bin"
for h in shaper capture; do
	cp "$repo/target/debug/u6e-$h" "$bin/" || { echo "no host build of u6e-$h" >&2; exit 1; }
	# Their run directories, as the image's tmpfiles.d makes them.
	[ -d "/run/u6e-$h" ] || { mkdir -m0750 "/run/u6e-$h" && made+=("/run/u6e-$h"); }
done

# unit <file name>: the heredoc prep-rootfs.sh writes it from.
unit() {
	sed -n "/^cat > \$RF\/etc\/systemd\/system\/$1 <<'UNIT'\$/,/^UNIT\$/p" "$repo/prep-rootfs.sh" | sed '1d;$d'
}
# ECM's files where ECM is loaded, else /proc/sys files of the same kind.
ecm=/proc/sys/net/ecm
if [ -d $ecm ]; then
	stand_in=(-e "s#^##")
else
	stand_in=(-e "s#$ecm/defunct_by_mac#/proc/sys/net/ipv4/conf/lo/rp_filter#"
		-e "s#$ecm/defunct_by_iface#/proc/sys/net/ipv4/conf/lo/log_martians#")
fi

bad=0
for h in shaper capture; do
	unit "u6e-$h.socket" | sed -e "s#^SocketGroup=u6e-agent#SocketGroup=root#" > "$units/u6e-unit-test-$h.socket"
	unit "u6e-$h@.service" | sed "${stand_in[@]}" -e "s#/usr/local/sbin/u6e-$h#$bin/u6e-$h#" > "$units/u6e-unit-test-$h@.service"
	for f in "$units/u6e-unit-test-$h.socket" "$units/u6e-unit-test-$h@.service"; do
		[ -s "$f" ] || { echo "FAIL: prep-rootfs.sh writes no ${f##*/u6e-unit-test-}"; bad=1; }
	done
done
systemctl daemon-reload
for h in shaper capture; do
	systemctl start "u6e-unit-test-$h.socket" || { echo "FAIL: u6e-$h.socket does not start"; bad=1; continue; }
	sock=$(systemctl show -P Listen "u6e-unit-test-$h.socket" | cut -d' ' -f1)
	python3 -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.close()' "$sock"
	# The instance, once its last command has ended (it fails: no agent).
	inst=
	for _ in $(seq 100); do
		inst=$(systemctl list-units --all --plain --no-legend "u6e-unit-test-$h@*" | awk '{print $1}' | head -1)
		[ -n "$inst" ] && case $(systemctl show -P ActiveState "$inst") in failed | inactive) break ;; esac
		sleep 0.1
	done
	[ -n "$inst" ] || { echo "FAIL: u6e-$h@: no instance ran"; bad=1; continue; }
	main=$(systemctl show -P ExecMainStatus "$inst")
	post=$(systemctl show -P ExecStopPost "$inst" | grep -o 'code=[a-z]* ; status=[0-9]*' | head -1)
	said=$(journalctl -q -o cat _SYSTEMD_INVOCATION_ID="$(systemctl show -P InvocationID "$inst")" | grep "^u6e-$h: " | head -1)
	# 200 and up: systemd failed the command before it ran its binary.
	if [ "$main" -ge 200 ] || [ -z "$said" ]; then
		echo "FAIL: u6e-$h@ ExecStart did not run: status $main ($(systemctl show -P Result "$inst"))"
		bad=1
	else
		echo "ok:   u6e-$h@ ExecStart ran in its sandbox, status $main: $said"
	fi
	if [ "$post" = "code=exited ; status=0" ]; then
		echo "ok:   u6e-$h@ ExecStopPost ran in its sandbox, $post"
	else
		echo "FAIL: u6e-$h@ ExecStopPost: ${post:-did not run}"
		bad=1
	fi
done
exit $bad

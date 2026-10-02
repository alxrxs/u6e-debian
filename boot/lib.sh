# shellcheck shell=bash
# Sourced by the boot tooling: the site configuration and SSH to the AP's two
# systems. Stock's sshd takes the controller's device password, our image
# root's key; each refuses the other with the same "Permission denied".
U6E=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../site.conf.example
. "$U6E/site.conf"
AP=${MGMT_ADDR%/*}
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)
U6E_TMP=$(mktemp -d); trap 'rm -rf "$U6E_TMP"' EXIT
export APPW=$U6E_TMP/appw U6E_STOCK=$STOCK_USER@$AP

# Both take [-n] <command> and T=<seconds> (default 60) as the timeout of the
# whole session; -n detaches ssh from stdin.
stock_pw() { [ -s "$APPW" ] || stock_password > "$APPW"; }
ap_stock() { # run on the stock firmware
	local o=(); [ "${1:-}" = -n ] && { o=(-n); shift; }
	stock_pw
	timeout "${T:-60}" sshpass -f "$APPW" ssh "${SSH_OPTS[@]}" "${o[@]}" -o PubkeyAuthentication=no "$U6E_STOCK" "$@"
}
ap_root() { # run on our image
	local o=(); [ "${1:-}" = -n ] && { o=(-n); shift; }
	timeout "${T:-60}" ssh "${SSH_OPTS[@]}" "${o[@]}" -o BatchMode=yes "root@$AP" "$@"
}

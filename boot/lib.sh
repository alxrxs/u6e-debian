# shellcheck shell=bash
# Sourced by the boot tooling: the site configuration and SSH to the AP's two
# systems. Stock's sshd takes the controller's device password, our image
# root's key; each refuses the other with the same "Permission denied".
U6E=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../site.conf.example
. "$U6E/site.conf"
AP=${MGMT_ADDR%/*}
# Host keys: with AP_KNOWN_HOSTS, each system's keys are checked against its
# own entry there, our image's as AP_HOSTNAME and stock's, which answers on the
# same address, as AP_HOSTNAME-stock. Without it nothing is checked, as an
# image without ssh_host_key makes new keys at every boot.
SSH_OPTS=(-o LogLevel=ERROR -o ConnectTimeout=5)
if [ -n "${AP_KNOWN_HOSTS:-}" ]; then
	SSH_OPTS+=(-o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$AP_KNOWN_HOSTS" -o GlobalKnownHostsFile=/dev/null)
	ROOT_KEY=(-o "HostKeyAlias=$AP_HOSTNAME") STOCK_KEY=(-o "HostKeyAlias=$AP_HOSTNAME-stock")
else
	SSH_OPTS+=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
	ROOT_KEY=() STOCK_KEY=()
fi
U6E_TMP=$(mktemp -d); trap 'rm -rf "$U6E_TMP"' EXIT
export APPW=$U6E_TMP/appw U6E_STOCK=$STOCK_USER@$AP
# The stock login up to its target, for ap_stock and boot/ext4map.py.
STOCK_SSH=(sshpass -f "$APPW" ssh "${SSH_OPTS[@]}" "${STOCK_KEY[@]}" -o PubkeyAuthentication=no)

# Both take [-n] <command> and T=<seconds> (default 60) as the timeout of the
# whole session; -n detaches ssh from stdin.
stock_pw() { [ -s "$APPW" ] || stock_password > "$APPW"; }
ap_stock() { # run on the stock firmware
	local o=(); [ "${1:-}" = -n ] && { o=(-n); shift; }
	stock_pw
	timeout "${T:-60}" "${STOCK_SSH[@]}" "${o[@]}" "$U6E_STOCK" "$@"
}
ap_root() { # run on our image
	local o=(); [ "${1:-}" = -n ] && { o=(-n); shift; }
	timeout "${T:-60}" ssh "${SSH_OPTS[@]}" "${ROOT_KEY[@]}" "${o[@]}" -o BatchMode=yes "root@$AP" "$@"
}

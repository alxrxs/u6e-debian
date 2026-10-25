# shellcheck shell=bash
# Sourced by the test tools: the site configuration, SSH to the AP, and the
# test client (TEST_CLIENT in site.conf): an SSH target with a Wi-Fi card
# (TEST_IFACE) in its own network namespace (TEST_NETNS), whose host key is
# checked as ssh checks any (your known_hosts): it is sent the test account.
# shellcheck source=../boot/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../boot/lib.sh"
TSSH=(ssh -o BatchMode=yes -o LogLevel=ERROR "$TEST_CLIENT")
client() { timeout "${T:-120}" "${TSSH[@]}" "$@"; }

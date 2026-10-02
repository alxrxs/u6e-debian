#!/bin/bash
# Print which system the AP is running: debian (root key login), stock (device
# password login) or down. Both sshds refuse the other's login with the same
# "Permission denied", so only a successful login tells them apart.
set -uo pipefail
. "$(dirname "$0")/lib.sh"
if T=10 ap_root -n true 2>/dev/null; then echo debian; exit 0; fi
if T=10 ap_stock -n true 2>/dev/null; then echo stock; exit 0; fi
echo down

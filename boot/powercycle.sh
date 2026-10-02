#!/bin/bash
# Power-cycle the AP through the site's power_off/power_on (site.conf), e.g. a
# smart plug on its PoE injector. Every boot cycle disarms itself first, so a
# power cycle always comes back in the stock firmware - and wipes the DRAM that
# pstore lives in.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
power_off; sleep 8
power_on; echo "power restored at $(date +%T)"

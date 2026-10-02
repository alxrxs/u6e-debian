#!/bin/bash
# Power-cycle the AP through the site's power_off/power_on (site.conf), e.g. a
# smart plug on its PoE injector. It comes back in stock unless a persistent
# image (U6E_PERSIST) had re-armed its boot, and it wipes the DRAM that pstore
# lives in.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
power_off; sleep 8
power_on; echo "power restored at $(date +%T)"

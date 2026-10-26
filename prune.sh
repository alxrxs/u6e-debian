#!/bin/bash
# Prune this checkout's kept images by deploy.sh's retention rule, as
# deploy.sh does after a run (ap-image.sh's prune_images: the stamps, the
# deploy runner's keeps from site.conf, the newest KEEP_IMAGES of each AP).
# Run as root:
#   ./prune.sh --dry-run    (list what the rule would remove)
#   ./prune.sh              (remove it, under the lock deploy.sh and the
#                            runner's stagings take)
set -euo pipefail
cd "$(dirname "$0")"
. ./site.conf
. ./ap-image.sh
if [ "${1:-}" = --dry-run ]; then
	DRY_RUN=1 prune_images
	exit
fi
exec {lock}< images
flock -n "$lock" || { echo "images/ is locked: a rollout or a deploy is under way" >&2; exit 1; }
prune_images

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Caution SEZC
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Polls URL every 0.2 s for SECONDS seconds and reports the longest run of
# failures (the cutover interruption) and when service recovered.
# Usage: measure_cutover.sh https://app.example.com/.well-known/caution/health 120
set -euo pipefail
URL=$1; DURATION=$2
end=$(( $(date +%s) + DURATION )); gap_start=""; longest=0; recovered=""
while [ "$(date +%s)" -lt "$end" ]; do
    now=$(date +%s.%N)
    if curl -fsS --max-time 2 -o /dev/null "$URL"; then
        if [ -n "$gap_start" ]; then
            gap=$(echo "$now - $gap_start" | bc)
            if [ "$(echo "$gap > $longest" | bc)" = 1 ]; then longest=$gap; recovered=$now; fi
            gap_start=""
        fi
    elif [ -z "$gap_start" ]; then
        gap_start=$now
    fi
    sleep 0.2
done
[ -n "$gap_start" ] && echo "UNRECOVERED since $gap_start" && exit 1
echo "longest_interruption_seconds=$longest recovered_at=$recovered"

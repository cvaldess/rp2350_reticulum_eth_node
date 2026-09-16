#!/usr/bin/env bash
# Overnight soak from the rnsd host (Pine64 "linbox"): every INTERVAL seconds probe both nodes
# through Reticulum and snapshot the path table. Run inside tmux so it survives the SSH session:
#
#   tmux new -d -s soak 'bash ~/pine64_soak.sh ~/soak.log 300'
#
# Bench 1 (Pico 2, TCP + LoRa) answers directly over TCP; bench 2 (LoRa only) is reached through
# bench 1, so every probe to it exercises the LoRa <-> TCP transport path in both directions.
LOG=${1:-$HOME/soak.log}
INTERVAL=${2:-300}
RNS=$HOME/rns-venv/bin
BENCH1=cae43b192c28e13f37f86f08c977ddd0   # identity in the SE050 since 2026-09-16 (was 7627f0e8... with software keys)
BENCH2=cf2dae5f96da01003461109abc18e42a
export PYTHONIOENCODING=utf-8

echo "$(date '+%F %T') --- soak start interval=${INTERVAL}s" >> "$LOG"
while true; do
    for h in $BENCH1 $BENCH2; do
        out=$(timeout 120 "$RNS/rnprobe" rp2350node.status "$h" -n 3 -w 2 -t 20 2>&1 | grep -E "Round-trip|Sent [0-9]+, received|timed out|No path" | tr '\n' ' ')
        echo "$(date '+%F %T') probe ${h:0:8} $out" >> "$LOG"
    done
    echo "$(date '+%F %T') paths: $("$RNS/rnpath" -t 2>&1 | grep -c 'hop')" >> "$LOG"
    sleep "$INTERVAL"
done

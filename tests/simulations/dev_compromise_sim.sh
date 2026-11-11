#!/bin/sh
# Harmless reproduction of a fake-recruiter "coding test" compromise, to check
# that an endpoint's agent (1.24.0+) raises the ioa_dev_* alerts
# (docs/operations/ioa.md). Run as a normal user on a Linux endpoint with
# node and python3:
#
#     sh tests/simulations/dev_compromise_sim.sh
#
# What it does, and nothing else:
#   1. a throwaway node project writes ~/.adsiem-sim/stage.py (a hidden home
#      folder, like the real second stages in ~/.n2 or ~/.npl);
#   2. node runs it with python3 (the file is the interpreter's argument);
#   3. the stage opens one byte of a FAKE key, ~/.ssh/id_adsiem_sim, created
#      here (your real keys are never opened);
#   4. it opens a TCP connection to portquiz.net:1224 (answers on any port)
#      and closes it, sending nothing.
# Everything it created is removed at the end.
#
# Expected alerts within a minute: IOA: Project code run by an interpreter
# dropped a hidden program and ran it; IOA: Project interpreter or
# user-folder program read a credential store; IOA: Project interpreter
# connected to a public address on an unusual port; and SSH Key or Cloud
# Token Read by an Unexpected Program.
set -eu

command -v node >/dev/null || { echo "needs node"; exit 1; }
command -v python3 >/dev/null || { echo "needs python3"; exit 1; }

if [ ! -d "$HOME/.ssh" ]; then
  mkdir -m 700 "$HOME/.ssh"
  echo "note: ~/.ssh did not exist; the agent marks new folders within 10 minutes (or restart it), then run again"
fi
fake="$HOME/.ssh/id_adsiem_sim"
printf 'ADSIEM SIMULATION - NOT A KEY\n' > "$fake"
chmod 600 "$fake"

proj=$(mktemp -d)
trap 'rm -rf "$proj" "$HOME/.adsiem-sim"; rm -f "$fake"' EXIT

cat > "$proj/index.js" <<'JS'
// The "project": drops a hidden stage and runs it, as a stealer's loader does.
const fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process');
const dir = path.join(os.homedir(), '.adsiem-sim');
fs.mkdirSync(dir, { recursive: true });
const stage = path.join(dir, 'stage.py');
fs.writeFileSync(stage, `
import os, socket
key = os.path.expanduser("~/.ssh/id_adsiem_sim")
with open(key, "rb") as f:
    f.read(1)
print("stage: opened", key)
try:
    s = socket.create_connection(("portquiz.net", 1224), timeout=5)
    s.close()
    print("stage: connected to portquiz.net:1224")
except OSError as e:
    print("stage: connection failed (still shows as an attempt only if it reached the network):", e)
`);
console.log('project: wrote', stage);
cp.spawnSync('python3', [stage], { stdio: 'inherit' });
JS

(cd "$proj" && node index.js)
sleep 2
echo "done: check the dashboard for the IOA alerts of this host"

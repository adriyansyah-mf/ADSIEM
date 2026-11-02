# Process tree on an alert

Alert page → **Process tree** tab (`GET /api/alerts/{id}/process-tree`, permission `alerts:read`, built in `server-api/app/services/process_tree.py`).

## What it shows

- The process the alert is about (★): the pid in the alert's event (`process.pid`, `ProcessId` or `PID`).
- Its ancestors, up to 10 levels; a parent with no recorded start is shown from its child's `ParentImage` (hollow dot).
- Its children and grandchildren (up to 100), started before the alert + 1 hour.
- For each process: file writes, network connections, DNS queries and known-malware events, and its exit (Linux).

## How processes are matched

No sensor gives a process a unique id, so a process is the most recent process start with its pid **on the alert's agent** before the moment that matters (its child's start, or the alert), looking back 3 days. Events belong to the latest start of their pid at or before them. Process starts come from `linux_process_exec` (eBPF), `windows_etw_process` (agent ETW) and Sysmon event 1; activity from `linux_file_event`, `windows_etw_file`, `linux_network_connect` / `linux_network_accept`, `windows_etw_network`, `linux_dns_query`, `windows_etw_dns`, `known_malware`, `linux_process_exit`. Hosts with only Windows Security 4688 or Sysmon 3/11 (no pid) show the alert's process alone.

Times are when the server received each event, so order within a second or two can be off when an agent buffered.

## Response

From the selected process (each asks once more):

| Action | What it does | Needs |
|---|---|---|
| Kill process | task `kill_process` with its pid; the agent kills whatever has that pid **now** | `agents:manage` |
| Quarantine file | task `quarantine_file` on its image (restore with `restore_file`) | `agents:manage` |
| Known malware | adds its SHA-256 to Malware hashes (only when a SHA-256 is known: Sysmon, known-malware events) | `rules:create` |
| Isolate host | `POST /api/agents/{id}/isolate` | `agents:manage` |

# AI skills

Skills are the procedures the AI investigator (**Investigate with AI** on a
case) follows for a kind of attack: which evidence to collect with which
tools and artifacts, how to tell a true positive from a false positive, and
what the report must cover. A skill is how the SOC's experience reaches the
model. Without skills, the investigator plans from the model's general
knowledge, which varies from model to model.

## How the investigator uses them

The investigator works the way an agent uses skills:

1. Its instructions list every **enabled** skill by name and description
   (at most 40). That costs a few lines of context, not the full documents.
2. When the case matches a description, it calls `load_skill(name)` and gets
   the full instructions. It may load up to 4 skills per investigation.
3. It follows the skill and adapts it to what the evidence shows. A skill
   tells it what to check; it is not evidence. Every claim in the report
   still cites an `evidence_id`.

The run's **Activity** tab shows each skill loaded ("Loaded skill …"), so an
analyst sees which procedure the AI followed. `load_skill` is a tier-0
action: it reads a document and touches no host.

## Built-in skills

They ship in `skills/*.md` and are synced at every start: new ones are added
enabled, changed ones updated, and your on/off choice is kept.

| Skill | When |
|---|---|
| `webshell-investigation` | a web server or its user ran a shell or recon, a script appeared in a web root, requests with cmd/exec parameters |
| `cryptominer-investigation` | unknown high-CPU process, binary in /tmp or /dev/shm, pool connections, XMRig or kinsing strings |
| `ransomware-investigation` | RansomGuard canaries, mass renames, ransom notes, shadow-copy deletion |
| `bruteforce-then-login` | SSH/RDP/web brute force or spraying, above all when a login then succeeds |
| `lateral-movement-investigation` | remote logins or remote-admin connections that are new for a host or account |
| `ot-ics-attack-investigation` | Modbus/DNP3 writes, PLC programming or stop, scans, OT exposed to the internet, ICS signatures |
| `phishing-initial-access` | Office/LibreOffice starting a shell or script host, Office dropping programs, ClickFix, the Office IOA chains |
| `credential-access-investigation` | LSASS read or dumped, /etc/shadow read, browser/wallet credential stores, credential process memory |
| `c2-beaconing-investigation` | periodic beaconing, C2 blocked by the firewall, suspicious-TLD DNS, dangerous outbound services, odd listeners |
| `data-exfiltration-investigation` | large or HTTP POST uploads, file-sharing destinations, archives staged before a transfer |
| `linux-privilege-escalation` | sudo/su to root, sudoers or PAM written, privilege change to root, privileged group added |
| `windows-persistence-lolbins` | encoded PowerShell, script blocks, new services and scheduled tasks, Defender disabled, LOLBins |
| `defense-evasion-tampering` | logs cleared, SIEM agent tampered or stopped, sensor exclusions, backups deleted |
| `web-application-attack` | SQLi, XSS, NoSQL, Log4Shell, LFI, WordPress probes: whether any request succeeded |
| `malicious-project-supply-chain` | malicious repositories or packages (fake job tests), interpreters dropping programs or reading credential stores |

`tests/server-api/test_ai_skills.int.py` checks that every artifact and tool
a built-in skill names exists. A skill that sends the investigator to a
missing artifact fails CI.

## Your own skills

**Response → AI skills → New skill** (admins). Fields:

- **Name:** lowercase-hyphenated, for example `phishing-investigation`.
  This is what the AI calls it by.
- **Description:** when to use it. The AI chooses skills by this text alone,
  so name the alerts, log types and signs the skill covers.
- **Instructions:** Markdown. What works best:
  - Numbered steps that name real tools (`search_events`,
    `correlate_entity`, `process_tree`, ...) and artifacts
    (`Linux.Sys.Persistence`, `Windows.EventLogs.Query` with `Channel` and
    `EventIDs`, ...). **Live response → Artifacts** lists them with their
    parameters.
  - Explicit true-positive and false-positive criteria for your
    environment ("our backup server rsyncs nightly from 10.0.5.20").
  - A "report must cover" list.

To change a built-in skill, **save a copy** (copy icon), edit the copy, then
turn the original off. Built-in text is refreshed at every start, so an edit
in place would be lost.

API: `GET /api/ai-skills` (alerts:read), and `POST`, `PATCH /{id}`,
`DELETE /{id}` (settings:manage). Built-in skills accept only
`{"is_enabled": …}` and cannot be deleted.

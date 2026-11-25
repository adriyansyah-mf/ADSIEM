# Security Policy

ADSIEM is security software: its agent runs as root/SYSTEM, and its server holds logs,
credentials and response actions for every enrolled host. We take reports seriously and
appreciate the time you spend on them.

## Supported versions

| Component | Supported |
|---|---|
| Server, worker and dashboard | The latest commit on the default branch |
| Endpoint agent | The latest minor release (currently `agent-v1.36.x`) |
| Older agents | Fixes are shipped in a new release; update them from the **Agent updates** page |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub:
**Security → Advisories → [Report a vulnerability](https://github.com/adriyansyah-mf/ADSIEM/security/advisories/new)**.

Please include:

- the affected component (agent, server-api, worker, dashboard, packaging) and version;
- the steps to reproduce, or a proof of concept;
- the impact you expect (for example: agent token theft, privilege escalation on an
  endpoint, command execution on the server, prompt injection that triggers a response
  action, bypass of an approval gate);
- any suggested fix.

## What to expect

- An acknowledgement within **3 business days**.
- An initial assessment and severity (CVSS) within **10 business days**.
- A fix as soon as practical, usually within **90 days**, depending on severity. Critical
  issues are fixed first.
- A GitHub Security Advisory when the fix is released, crediting you unless you prefer
  otherwise.

Please give us a reasonable chance to release a fix before you disclose the issue publicly.

## Scope

In scope:

- the Go agent (`agent/`) and its packages (`.deb`, `.rpm`, `.msi`, `.zip`), including
  self-update, anti-tamper and live response;
- the API (`server-api/`), worker (`worker/`), syslog receiver and dashboard (`dashboard/`);
- the AI layer: prompt injection that changes a verdict, closes an alert or runs a response
  action without analyst approval;
- the Docker Compose and nginx configuration shipped in this repository.

Out of scope:

- deployments that keep the bootstrap credentials (`admin` / `admin123`) or the example
  secrets from `.env.example`;
- findings that need an already compromised administrator account or root on the server;
- vulnerabilities in third-party services (LLM providers, threat-intel feeds) and in
  bundled third-party detection rules, which should go to their upstream projects;
- denial of service through traffic volume alone.

## Safe harbour

We will not pursue legal action against research done in good faith that follows this
policy: test only systems you own or are allowed to test, avoid privacy violations and data
destruction, and stop and report as soon as you have shown the issue.

## Hardening your deployment

See [Production Deployment](README.md#production-deployment) in the README: change all
secrets, rotate enrollment tokens, put the server behind TLS, and keep agents updated.

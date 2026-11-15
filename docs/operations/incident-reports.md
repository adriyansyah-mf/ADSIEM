# Incident reports

An incident report describes one case for people outside the SOC, such as
management, auditors or the system owner. It covers what happened, what was
affected, the evidence, what was done, and what to do next. The report is
written in Bahasa Indonesia or English.

## Writing one

1. Open a case and choose **Incident report → Write draft**.
2. Pick the language, a classification and, optionally, who it is for.
3. Leave **Let AI write…** on so the model writes the prose. With it off, the
   draft still has every fact.

The draft is built from the case (`server-api/app/services/incident_report.py`):

| Section | Comes from |
|---|---|
| Summary | The AI investigation's executive summary, or the case description |
| Assets and scope | Hosts of the linked alerts and the case's affected hosts |
| Timeline | Linked alerts, plus timeline findings from the investigation |
| Indicators | The case's IoC keys, extracted indicators and alert source IPs |
| Analysis | Verified findings of the latest finished AI investigation, each citing evidence as `[E1]` |
| Actions taken | The case's history in the audit log, and response tasks (isolate, block, kill, quarantine, scans) on the affected hosts since the case opened |
| Recommendations | The investigation's recommended actions |
| Evidence annex | Evidence the findings cite, plus pinned evidence (not restricted items), with SHA-256 |

Unverified investigation claims are left out.

**With AI**, the model rewrites the summary, analysis, impact, recommendations
and conclusion from these facts:

- The case data goes in as data. The prompt tells the model never to follow
  instructions found in it, because alert text can come from an attacker.
- The model may cite only the `[E#]` labels of the evidence annex. Any other
  citation is removed.
- If the model fails or returns something unusable, the factual draft stays.

## Editing

A draft can be edited on its page:

- the title, classification, priority and audience;
- every text section;
- the timeline, actions and indicators, row by row.

**Rebuild from case** writes the draft again from the case as it is now, for
example after a new investigation finishes. It replaces your edits.
**Preview PDF** shows the draft with a DRAFT watermark.

## Finalizing

An admin presses **Finalize**. The report then:

- gets a number, `IR-<year>-<0001>`, in order across the platform;
- is rendered to PDF once, and that exact file is stored;
- has its SHA-256 recorded, along with a hash of its content (printed in the
  footer as the integrity code);
- can no longer be edited, rebuilt or deleted.

Every download of a final report gives the same file. Creating, finalizing,
downloading and deleting a draft are written to the audit log.

## Checking a copy

Open **Reports → Verify a report** and pick the PDF:

- Your browser computes the file's SHA-256 and sends only the hash.
- A match names the report, who finalized it and when.
- Any change to the file, even one byte, means no match.
- Results are limited to your group.

API: `POST /api/incident-reports/verify {"sha256": "..."}`.

## The PDF

- **Header:** organization name (Settings → Organization Name), title, and a
  table with number, date, classification, priority, case, audience, author
  and approver.
- **Body:** nine numbered sections, then the evidence annex.
- **Every page:** the classification at the top and bottom, the number or
  DRAFT, the integrity code, and "Page x of y".

## API

| Method | Path | Who |
|---|---|---|
| POST | `/api/cases/{case_id}/incident-reports` `{language, use_ai, classification, audience}` | `cases:manage` |
| GET | `/api/incident-reports?status=&case_id=&q=` | `alerts:read` |
| GET / PUT | `/api/incident-reports/{id}` (PUT on drafts only) | read / `cases:manage` |
| POST | `/api/incident-reports/{id}/regenerate?use_ai=` | `cases:manage`, drafts |
| POST | `/api/incident-reports/{id}/finalize` | admin or superadmin |
| GET | `/api/incident-reports/{id}/pdf` | `alerts:read` |
| POST | `/api/incident-reports/verify` | `alerts:read` |
| DELETE | `/api/incident-reports/{id}` | `cases:manage`, drafts |

Everything is scoped to the caller's group.

The **Periodic summary** tab still produces the period PDF it did before
(`/api/reports/generate`).

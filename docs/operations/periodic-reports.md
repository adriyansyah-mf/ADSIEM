# Period summary

**Reports → Period summary** shows how a date range went, against the same
length of time just before it, and turns that into a PDF for management.

## On the page

Pick a range: **Last 7 days**, **Last 30 days**, **This month**, **Last month**,
or your own dates. Days start at midnight in your browser's time zone.

| Figure | Meaning |
|---|---|
| Alerts | Alerts raised, and the change from the period before |
| Cases opened | Cases opened, the change from before, how many closed in the period, and how many are still open |
| Mean time to acknowledge / resolve | From an alert being raised to being acknowledged or resolved, for alerts of the period |
| Exploited vulnerabilities open (KEV) | Open CVEs on CISA's Known Exploited list, the hosts that have them, and agents online |
| Alerts per day | Stacked by critical, high and the rest |
| Rankings | Most frequent rules, hosts with most alerts, top source IPs, MITRE techniques, AI triage outcome, and the most widespread KEV CVEs |
| Notable cases | High and critical cases opened in the period, plus incident reports finalized in it |

Everything is limited to your group. A superadmin sees all groups.

## The PDF

**Generate PDF** writes the report in Bahasa Indonesia or English. It
contains:

- an AI executive summary (optional, from the same numbers);
- the key figures with their change;
- the daily chart;
- the tables listed above;
- the organization name (Settings → Organization Name) and page numbers.

The AI gets the numbers as data, and rule and host names are marked as
possibly attacker-written. It is told to use only those numbers. With the AI
off, or when no model is set up, the PDF has everything except the summary.

Each generated PDF is kept, with the numbers it showed, under **Generated
before**, so the same file can be downloaded again later. Generating one is
written to the audit log.

## API

| Method | Path |
|---|---|
| GET | `/api/reports/summary?date_from=&date_to=&tz=` (at most 400 days) |
| POST | `/api/reports/generate` `{date_from, date_to, language: "id"/"en", tz, use_ai}` returns the PDF; header `X-Report-Id` |
| GET | `/api/reports/history` |
| GET | `/api/reports/history/{id}/pdf` |

All need `alerts:read`. Every figure comes from SQL aggregates
(`server-api/app/services/periodic_report.py`), so a long range costs about
the same as a short one.

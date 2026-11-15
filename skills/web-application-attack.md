---
name: web-application-attack
description: Attacks against a web application seen in web or WAF logs - SQL injection (including "SQL injection reached database query"), XSS, NoSQL injection, Log4Shell, path traversal or LFI, PHP execution probes in upload folders, WordPress enumeration, XML-RPC abuse or admin login probing, default-credential login attempts. Separates scanning noise from an attempt that succeeded.
---

# Web application attack investigation

Most web attack alerts are automated scanners that fail. The question is
almost always: **did any request succeed?** Answer that before anything
else.

## 1. Attempt or success?
- `search_events` on the web logs for the source IP and URL: the status
  code and response size of each malicious request. Mostly 403, 404 or 400
  with identical sizes means blocked or failed. A 200 with a size that
  differs from the normal page, a 500 from a SQL error, or a sudden large
  response is the place to look.
- SQL injection: "SQL Injection Reached Database Query" (database logs) or
  SQL errors in the application logs mean the input reached the database.
  `UNION SELECT` / `information_schema` requests with growing responses
  indicate data extraction.
- Log4Shell / JNDI: an outbound LDAP/RMI/HTTP connection **from the
  server** to the attacker right after the request proves execution
  (`Linux.Network.Netstat`, `search_events` for the server's outbound
  connections).
- PHP execution probes, file upload or LFI: did a new file appear in the
  web root, or did the web server user run a shell? If yes, switch to the
  webshell-investigation skill.
- Login probing (WordPress, default credentials): any successful login
  from the attacking IP? If yes, see the bruteforce-then-login skill.

## 2. The attacker
`pivot_ioc` and `correlate_entity` on the source IP: other targets, earlier
reconnaissance, reputation. A scanner sweeping many sites is noise. One
that came back to a single URL with variations is a person.

## 3. If it succeeded
What the attacker reached: data read (the tables in the injected queries),
accounts created, files written, and commands run as the web user. Check
whether the vulnerable parameter or plugin is still exposed.

## Verdict
- **True positive (compromise):** evidence that a request executed or
  extracted data: a successful response with attacker data, a database
  query, an outbound callback, a new file, or a shell.
- **True positive (attempt only):** targeted, repeated exploitation of one
  application with no success. Report the exposure and a lower severity.
- **False positive:** a sanctioned vulnerability scan (known scanner IP and
  window), or application traffic that matched a pattern (search terms
  containing SQL words, rich text with HTML).

## Report must cover
The application and the vulnerable endpoint or parameter, success or not
(with the evidence), the data or access obtained, the attacker IPs, and
whether the hole is still open. The recommended actions: patch or disable
the vulnerable component, block the source, add WAF rules for the
parameter, and rotate the database or application credentials if a
request succeeded.

---
name: webshell-investigation
description: A web server or its user (www-data, apache, nginx, IIS AppPool) ran a shell or recon commands, a script file appeared in a web root, or HTTP requests hit cmd/exec parameters. Confirms a webshell, finds the file and the entry point, and scopes what the attacker did.
---

# Webshell investigation

Goal: decide whether a webshell ran, find the file and how it got there, and
scope what the attacker did with it.

## 1. Anchor on the process evidence
- `process_tree` on the alerted host for the shell's PID (or `search_events`
  with `log_type: linux_process_exec` and the host): the parent should be
  apache2 / httpd / nginx / php-fpm / w3wp. Note the user (uid 33 is www-data
  on Debian/Ubuntu, 48 apache on RHEL) and every child command line.
- Recon right after the shell (`id`, `whoami`, `uname -a`, `cat /etc/passwd`,
  `find / -perm -o+w`, `sudo -l`, reading `debian.cnf` or wp-config.php) means
  a human operator is at the keyboard.

## 2. Find the file
- `search_events` for web access logs on the host (nginx_access,
  apache_access) around the first shell. Look for POSTs or GETs with
  `cmd=`, `exec=`, `c=` parameters, `.php` files in upload folders, and one
  source IP hitting one file again and again.
- `run_artifact Linux.Search.FileFinder` with `SearchGlob` set to the web
  root (for example `/var/www/**/*.php`) and compare modification times with
  the first shell. On Windows use `Windows.Search.FileFinder`
  (`C:/inetpub/wwwroot/**`).
- `run_artifact Linux.Detection.Yara` with `Path` set to the web root.
- `run_artifact Generic.Collectors.File` on the suspected file, to read it
  and get its SHA256.
- A webshell is often deleted after use. A file gone from disk but present
  in access logs is still evidence.

## 3. Find the entry point
- What did the same source IP do before the first request to the shell?
  Typical entry points are upload forms, CMS plugin installs, setup or
  installer pages left reachable (`setup.php`, `install.php`), file inclusion,
  and default credentials on admin panels.
- `pivot_ioc` the source IP: other hosts, earlier alerts, threat intel.

## 4. Scope
- Persistence: `run_artifact Linux.Sys.Persistence`, looking for crontabs
  owned by the web user, systemd units, and `authorized_keys`.
- Outbound: `run_artifact Linux.Network.Netstat`, looking for reverse shells
  or downloads from the web user.
- Privilege escalation: `search_events` for sudo or su by the web user;
  `run_artifact Linux.Sys.Users`.
- Dropped tools: `run_artifact Linux.Detection.SuspiciousProcesses`, and
  `Linux.Search.FileFinder` on `/tmp/**`, `/var/tmp/**`, `/dev/shm/**`.

## Verdict
- **True positive:** the web server parent runs a shell with recon, or a
  script file in the web root executes commands from request parameters.
- **False positive:** the application itself shells out with a fixed command
  line on every request (`git log -1`, ImageMagick `convert`, `sendmail`).
  Confirm that the same command line recurs from many clients and that no
  recon follows.

## Report must cover
The file (path, hash, still present?), the entry point, the attacker IP(s),
the commands run, persistence found, and what the web user could reach. The
recommended actions: remove the file and close the entry point (fix the
vulnerable page), rotate the credentials the app exposed (DB password in its
config), block the source IP, and check other web hosts for the same file
hash.

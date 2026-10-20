# NEXT PHASE — dari "SIEM + EDR" ke EDR enterprise

**Tanggal:** 2026-10-21
**Basis:** `origin/feature/siem-implementation` @ `daa49cb` (agent v1.8.0)
**Cakupan:** gap antara kondisi agent/platform sekarang dan yang biasa dituntut pembeli enterprise (CrowdStrike / SentinelOne / Defender for Endpoint sebagai pembanding).

Setiap gap di bawah sudah dicek ke kode. "Belum ada" artinya tidak ditemukan di `agent/`, `server-api/`, `worker/` atau `docker-compose.prod.yml` pada commit di atas.

---

## Posisi sekarang (yang sudah ada)

- **Telemetri:** eBPF execve (`agent/internal/procexec`) dan connect/accept/bind/DNS (`agent/internal/netwatch`) di Linux; event log Windows via `EvtSubscribe` (`agent/internal/winevent`); FIM; hygiene Linux + Windows.
- **Deteksi:** Sigma di worker, deteksi lokal di agent yang tetap memblokir saat server down (`agent/internal/detect`, Linux).
- **Respons:** isolate / block IP (Linux nftables, Windows `netsh advfirewall`), kill_process / quarantine_file / restore_file (Linux), flow live response ala Velociraptor (Linux.* dan 20 Windows.*), SOAR dengan approval analis, AI investigation (collect-only).
- **Anti-tamper:** stop/offline/silent-logs alert, hash binary+config di heartbeat, anti-spoofing heartbeat, uninstall token (deb/rpm/MSI), service lock DACL di Windows, deteksi WFP blocker (5447).
- **Deploy:** `.deb`, `.rpm`, MSI, enrollment key dengan approval.

---

## Fase 1 — Paritas Windows (prioritas tertinggi, perkiraan minggu)

Gap paling kelihatan: di Windows agent hanya bisa isolate/block, dan visibilitas proses bergantung penuh pada Sysmon.

### 1.1 Respons Windows: kill, quarantine, integrity
- **Bukti:** `agent/internal/task/response_notlinux.go` mengembalikan `"kill_process requires Linux"`, `"quarantine_file requires Linux"`, `"restore_file requires Linux"`, `"agent_integrity requires Linux"`.
- **Kerjaan:** `response_windows.go` — `OpenProcess` + `TerminateProcess` (tolak PID kritis: System, csrss, lsass, wininit, services, agent sendiri); quarantine = pindah ke `%ProgramData%\SIEMAgent\quarantine` dengan ACL SYSTEM-only + metadata (hash, path asli, owner) yang kompatibel dengan format Linux; `CheckIntegrity` versi Windows.
- **Selesai bila:** SOAR node kill/quarantine jalan di host Windows; `tests/windows/smoke-msi.ps1` mencakup kill + quarantine + restore.

### 1.2 Sensor ETW sendiri (tanpa Sysmon, tanpa driver)
- **Bukti:** `agent/AGENTS.md` — "No eBPF/process-exec stream ... on Windows — use Sysmon".
- **Kerjaan:** paket `internal/etw` (user-mode, jalan sebagai SYSTEM): provider `Microsoft-Windows-Kernel-Process` (start/stop + command line + parent), `Microsoft-Windows-Kernel-Network`, `Microsoft-Windows-DNS-Client`, opsional `Microsoft-Windows-Kernel-File`. Output memakai logsource Sigma yang sama dengan Linux (`process_creation`, `network_connection`, `dns_query`) supaya rule bisa dipakai lintas OS.
- **Catatan:** tidak butuh sertifikat. Provider `Microsoft-Windows-Threat-Intelligence` butuh PPL/ELAM → di luar fase ini (lihat Fase 4).
- **Selesai bila:** host Windows tanpa Sysmon menghasilkan event proses + jaringan yang terdecode dan memicu rule.

### 1.3 Deteksi lokal + blokir di Windows
- **Bukti:** `agent/AGENTS.md` — "the nft engine has no Windows backend"; rule default (`detect/defaults.go`) hanya untuk auth.log / Apache.
- **Kerjaan:** backend `firewall` untuk Windows (WFP via `netsh` atau API), rule lokal untuk 4625 (brute force RDP/SMB).

---

## Fase 2 — Syarat pengadaan enterprise

Hal yang biasanya jadi checklist RFP sebelum fitur deteksi dilihat.

### 2.1 Auto-update agent
- **Bukti:** tidak ada mekanisme self-update / upgrade dari server.
- **Kerjaan:** server menyimpan versi target per grup; agent cek di heartbeat, unduh paket bertanda tangan, verifikasi signature + SHA-256, upgrade, lapor versi. Staged rollout (ring 0 → 1 → 2), pause, rollback. Upgrade tidak boleh memicu `agent_integrity_changed` (sudah di-handle: hash baru + versi baru = re-baseline).

### 2.2 SSO
- **Bukti:** tidak ada SAML / OIDC / LDAP di `server-api` maupun `dashboard`.
- **Kerjaan:** OIDC dulu (Azure AD / Google / Keycloak), mapping claim → group + role RBAC yang ada; SAML menyusul.

### 2.3 Hardening kanal agent → server
- **Bukti:** `agent/internal/client/client.go` tidak mengatur `tls.Config` sendiri — hanya trust store sistem + token.
- **Kerjaan:** pinning CA server (disimpan saat enrollment), opsional mTLS per agent (sertifikat diterbitkan saat enroll, dicabut saat agent dihapus).

### 2.4 Policy terpusat per grup
- **Kerjaan:** satu objek policy per grup: mode (detect-only / block), exclusion path/proses/hash, sensor on/off, rule lokal aktif, batas blokir. Agent menerapkan dari heartbeat, versi policy tercatat di audit log.

### 2.5 Signed release + SBOM
- **Kerjaan:** tanda tangan binary Windows (Authenticode, cert code signing biasa — bukan EV driver), signature paket deb/rpm, SBOM per rilis di `.github/workflows/agent-release.yml`.

---

## Fase 3 — Kedalaman deteksi dan pencegahan

### 3.1 YARA penuh
- **Bukti:** `agent/internal/task/yara.go` — matcher buatan sendiri, hanya teks + regex; `// hex patterns skipped for simplicity`; tidak ada `filesize`, `uint16(0)`, hitungan `#a`, modul `pe`/`elf`.
- **Kerjaan:** ganti dengan libyara (go-yara, perlu CGO → cek dampak ke build statis) atau YARA-X; scan otomatis saat FIM melihat file baru/berubah di path berisiko (`/tmp`, webroot, `Downloads`, `%TEMP%`).

### 3.2 Telemetri Linux tambahan
- **Bukti:** `procexec` hanya `sys_enter_execve`; `netwatch` hanya connect/bind/accept4/sendto.
- **Kerjaan (eBPF):** file open-for-write/rename/unlink per proses, `init_module`/`finit_module`, `ptrace`, `setuid`/`capset`, `memfd_create` + exec dari memfd, exit proses (untuk tree lengkap).

### 3.3 Pencegahan pre-exec di Linux
- **Bukti:** tidak ada BPF-LSM / fanotify.
- **Kerjaan:** BPF-LSM `bprm_check_security` untuk blokir eksekusi berdasarkan hash/path/parent (mis. web server → shell); fallback fanotify `FAN_OPEN_EXEC_PERM` untuk kernel tanpa BPF-LSM. Mode detect-only dulu, block lewat policy (2.4).

### 3.4 Anti-ransomware
- **Bukti:** tidak ada canary/honeyfile atau deteksi enkripsi massal.
- **Kerjaan:** canary file per host (FIM khusus), heuristik rename/write massal per proses (butuh 3.2), respons otomatis kill + isolate via policy.

### 3.5 Pemindaian memori
- **Bukti:** tidak ada akses `/proc/<pid>/mem` / `process_vm_readv` / `ReadProcessMemory`.
- **Kerjaan:** YARA atas memori proses (on-demand dari live response dulu), deteksi region RWX anonim.

---

## Fase 4 — Skala, ketersediaan, dan kepercayaan

### 4.1 HA data
- **Bukti:** `docker-compose.prod.yml` — `server-api` dan `worker` sudah 2 replika, PostgreSQL dan Elasticsearch single node.
- **Kerjaan:** Postgres dengan replika (Patroni atau managed), Elasticsearch ≥ 3 node, ILM hot/warm/delete, backup + uji restore terdokumentasi.

### 4.2 Uji beban terdokumentasi
- **Kerjaan:** angka resmi "N agent, X EPS, latensi alert p95" dengan hardware referensi; lanjutkan dari branch lokal `load-test` (belum di-push ke origin).

### 4.3 macOS
- **Kerjaan:** agent berbasis Endpoint Security framework — butuh Apple Developer ID, entitlement ES, notarization, profil MDM (System Extension + Full Disk Access).

### 4.4 Proteksi diri level kernel (Windows)
- **Konteks:** anti-tamper sekarang bersifat deteksi; SYSTEM masih bisa mematikan agent. Proteksi sesungguhnya (PPL anti-malware, ELAM, provider ETW Threat-Intelligence) hanya lewat keanggotaan Microsoft Virus Initiative. Driver kernel sendiri butuh EV cert + attestation signing Partner Center.
- **Keputusan bisnis**, bukan tugas engineering murni.

### 4.5 Validasi pihak ketiga
- MITRE ATT&CK Evaluations / AV-TEST / SE Labs, SOC 2 atau ISO 27001, program vulnerability disclosure. Tutup dulu temuan `AUDIT.md` (C-1 cross-tenant dll.) sebelum ini.

---

## Housekeeping kecil

- `agent/AGENTS.md` baris pertama masih "**Linux-only.** No Windows/macOS build" — sudah tidak benar sejak agent Windows; perbarui.
- Landing page draft (artifact, belum di repo) menampilkan tabel Linux vs Windows; perbarui begitu Fase 1 selesai.

## Urutan yang disarankan

| # | Item | Alasan |
|---|------|--------|
| 1 | 1.1 respons Windows | Paling cepat, gap paling terlihat |
| 2 | 1.2 ETW | Hilangkan ketergantungan pada Sysmon |
| 3 | 2.1 auto-update, 2.2 SSO | Syarat pengadaan paling umum |
| 4 | 3.1 YARA penuh, 3.2 telemetri Linux | Fondasi untuk pencegahan |
| 5 | 3.3 BPF-LSM, 3.4 anti-ransomware | Pembeda utama dari "SIEM + EDR" |
| 6 | 4.1 HA, 4.2 uji beban | Sebelum pelanggan besar pertama |

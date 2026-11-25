# Agent config dari dashboard (per group)

## Intent

Semua setting operasional di `config.yaml` agent harus bisa diatur dari
dashboard, supaya operator tidak perlu login ke tiap host dan mengedit file.
Field yang menyangkut keamanan dan identitas agent tetap hanya bisa diatur
lewat file lokal.

## Goals

- Setting operasional diatur **per group** di halaman Policies, di samping
  setting policy yang sudah ada.
- Agent menerapkannya sendiri setelah policy berubah, tanpa ada yang
  menyentuh host.
- `server.url` bisa dipindah dari dashboard tanpa risiko agent hilang:
  kalau URL baru gagal, agent kembali ke URL lama.
- Dashboard memperlihatkan apakah config sudah diterapkan di tiap agent, dan
  error-nya kalau ada.

## Non-goals

- Override per agent. Granularitasnya per group, sama seperti policy.
  Agent yang butuh setting lain dipindah ke group lain.
- Membuat semua modul bisa dikonfigurasi ulang tanpa restart (pendekatan B).
- Mengirim field keamanan dari server (lihat daftar di bawah).

## Anti-goals

- Agent tidak boleh terputus permanen dari server karena salah config,
  khususnya `server.url`.
- Agent tidak boleh terjebak restart berulang karena config yang sama.
- Field keamanan tidak boleh bisa diubah dari server, sekalipun server
  disusupi. Whitelist-nya ditegakkan di **agent**, bukan hanya di server.

## Approaches

- **A. Overlay lewat policy + restart otomatis (dipilih).** Policy group
  mendapat bagian `agent_config`. Agent menumpuknya di atas `config.yaml`
  lokal. Kalau ada field yang berubah, agent keluar dan service manager
  menyalakannya lagi. Ini memakai jalur versi dan heartbeat yang sudah ada,
  satu mekanisme untuk semua field, dan modul tidak perlu dirombak.
- B. Setiap modul bisa di-reload live. Tidak ada jeda restart, tetapi
  sekitar 15 modul (FIM, ETW, tailer logs, firewall, dll.) harus dirombak
  agar bisa start/stop dengan bersih. Pekerjaannya besar dan rawan bug.
- C. Gabungan, yaitu A ditambah sebagian field yang live. Bisa menyusul di
  atas A, jadi tidak perlu sekarang.

User memilih A. Alasannya, restart sekitar 10 detik setiap kali config
berubah itu wajar untuk agent. Wazuh juga merestart agent untuk config yang
dikirim server.

## Cara kerja sekarang (titik sentuh)

- Server: `server-api/app/services/agent_policy.py`.
  - `PolicySettings` (pydantic).
  - `effective(db, group_id)` dengan fallback group → DEFAULT_GROUP →
    built-in.
  - `version_of` = sha256 dari settings.
  - Agent mengambil policy lewat `GET /api/ingest/policy`.
  - Response heartbeat membawa `policy_version`.
- Agent: `agent/internal/policy/policy.go` menyimpan `policy.json` di state
  dir. `main.go` memanggil `polStore.Want(resp.PolicyVersion)`, lalu
  menerapkan Settings secara live.
- `config.yaml` dibaca sekali saat start. `config.Watch` hanya meng-hot-reload
  `agent.name`, `agent.group`, dan `server.url`.
- Windows: service SCM punya failure action restart dengan jeda 10 detik
  (`siem-agent.wxs`).
- Linux: `siem-agent.service` memakai `Restart=always` dengan
  `RestartSec=5s`.
- UI: `dashboard/src/pages/PoliciesPage.tsx`.

## Design

### Data

`PolicySettings` mendapat field `agent_config: AgentConfigOverlay | None`.
Overlay ini model pydantic yang strukturnya mengikuti `config.yaml`, dengan
semua field opsional. Field yang **tidak diisi** berarti "pakai nilai
lokal", bukan "kosongkan". Karena overlay ikut di settings, `version_of`
otomatis berubah dan agent mengambilnya lewat jalur `policy_version` yang
sudah ada. Tidak perlu tabel atau endpoint baru.

Kalau sebuah list diisi, list itu **menggantikan** list lokal, bukan
ditambahkan. Ini sama dengan semantik yaml sekarang (mis. `yara.watch_paths`
menggantikan default).

Field yang boleh di-overlay (whitelist):

| Bagian | Field |
|---|---|
| server | `url` (host sama saja, lihat bawah), `heartbeat_interval` |
| agent | `buffer_size` |
| logs | seluruh list (`path`, `type`, `enabled`) |
| fim | `enabled`, `watch_paths` |
| firewall | `enabled`, `backend`, `dry_run`, `protected_ips`, `isolation_release_after_offline_minutes` |
| netwatch | `enabled`, `snapshot_fallback` |
| etw | `mode`, `disabled_events` |
| detect | `enabled`, `rules`, `max_blocked`, `max_blocks_per_minute` |
| linux_sensor | `disabled`, `disabled_events` |
| ransomware | `disabled`, `canary_visible`, `allow_images` (bukan `canary_dirs`/`canary_names`: path yang ditulis agent sebagai SYSTEM/root) |
| yara | `watch_paths`, `max_file_size_mb` |
| memory_sweep | `disabled`, `interval_minutes` |
| evidence | `enabled`, `max_bytes`, `segment_bytes`, `reserved_bytes`, `max_event_bytes` |
| prevention, notify, project_scan, update | `disabled` |

Field yang **tetap lokal**:

- `agent.id`, `agent.name`, `agent.group`, `token`, `enrollment_token`,
  `state_dir`, `config_path`, `config_version`.
- `live_response.disable_commands`, `anti_tamper.unlock_service`,
  `update.trusted_keys`.
- Path yang ditulisi agent: `buffer.spill_path`, `firewall.state_path`,
  `evidence.dir`. Menulis ke path pilihan server dengan hak SYSTEM itu
  primitif yang berbahaya.

Field yang sudah diatur policy tidak diduplikasi:

- `ransomware.report_only`/`isolate` → `ransomware_mode`/`ransomware_isolate`.
- `yara.disabled` → `yara_on_access`.
- Policy `notify_user` dan `prevention_enabled` tetap mengatur perilaku live.

Saklar `*.disabled` di overlay berarti modulnya tidak dijalankan sama
sekali.

### Agent

1. **Saat start:** baca `config.yaml`, lalu `policy.json` yang tersimpan.
   Tumpuk overlay ke config (`config.ApplyOverlay(cfg, overlay)`) **sebelum**
   modul dibuat. Whitelist dipaksakan di sini: overlay di-decode ke struct Go
   yang hanya memuat field whitelist, sehingga field lain diabaikan walaupun
   server mengirimnya.
2. **Saat policy baru datang:** hitung config efektif yang baru dan bandingkan
   dengan yang sedang berjalan.
   - Sama → tidak ada tindakan.
   - Beda → tulis `policy.json`, catat `config_restart_for=<version>` di state
     dir, lalu keluar dengan kode non-zero supaya SCM/systemd menyalakannya
     lagi. Saat start berikutnya, overlay baru sudah terpakai (langkah 1).
   - Guard loop: kalau `config_restart_for` sudah sama dengan versi itu dan
     config efektif tetap berbeda, jangan restart lagi. Laporkan error.
3. **`server.url` berubah:** sebelum restart, uji URL baru dengan heartbeat
   ber-token, TLS terverifikasi, timeout 15 detik.
   - Gagal → jangan pakai, laporkan error lewat URL lama.
   - Berhasil → simpan URL lama sebagai `last_good_url` di state dir, lalu
     restart.
   - Setelah restart, kalau URL baru tidak tersambung sama sekali selama
     10 menit, agent kembali ke `last_good_url` dan menandai versi overlay
     itu sebagai ditolak, sehingga tidak dicoba lagi.
4. **Status:** heartbeat mengirim `config_version` (versi overlay yang sedang
   berjalan) dan `config_error` (kosong kalau tidak ada error).

5. **Overlay membuat agent gagal start** (keputusan builder):
   - Agent mencatat penghitung crash per versi overlay di state dir.
   - Kalau agent mati 3 kali dalam 10 menit setelah menerapkan versi V, start
     berikutnya memakai config lokal saja, menandai V ditolak, dan
     melaporkan `config_error`.
6. **Prioritas** (keputusan builder):
   - Overlay menang atas `config.yaml`.
   - `config.Watch` tetap meng-hot-reload `server.url` dari file hanya kalau
     overlay tidak mengisinya.
   - Edit lokal pada field lain tetap baru berlaku setelah restart manual,
     sama seperti sekarang. Edit file tidak memicu restart otomatis.
7. **Cara restart** (keputusan builder):
   - Windows: proses keluar tanpa melapor `SERVICE_STOPPED`, sehingga SCM
     menganggapnya crash dan menjalankan failure action. Alternatifnya,
     set flag `FailureActionsOnNonCrashFailures`.
   - Linux: cukup `Restart=always`.
   - Kalau tidak berjalan sebagai service (mode konsol/dev): jangan keluar,
     cukup log "restart diperlukan" dan laporkan di `config_error`.
   - Sebelum restart, tunggu jitter acak 0–60 detik supaya perubahan di
     DEFAULT group tidak merestart seluruh fleet di detik yang sama.
8. **Versi config** (keputusan builder):
   - `config_version` = hash dari `agent_config` saja, terpisah dari
     `policy_version` yang juga memuat ML false positive.
   - Server menghitung hash yang diharapkan per group dengan cara yang sama.
   - Overlay kosong → versi kosong, dihitung "diterapkan".
9. **Fallback group** (keputusan builder): ikut perilaku policy sekarang,
   yaitu satu baris utuh. Group yang punya baris policy sendiri dengan
   `agent_config` kosong memakai config lokal dan tidak mewarisi DEFAULT.
   UI menulis ini dengan jelas.

### Batas `server.url` (keputusan user)

Dari dashboard, `server.url` hanya boleh mengganti port dan/atau path di **host
yang sama** dengan URL di `config.yaml` lokal. Agent menolak overlay yang
host-nya berbeda, melaporkan `config_error`, dan memakai URL lokal. Server juga
menolaknya saat validasi. Pindah ke host lain tetap lewat file lokal. Ini
mencegah server yang disusupi mengalihkan agent ke host penyerang sambil
membawa token. Saklar `disabled` modul dan `update.disabled` tetap boleh diatur
dari dashboard: risikonya diterima, karena policy yang ada pun sudah bisa
mematikan proteksi.

### Server dan dashboard

- Pydantic memvalidasi rentang nilai, misalnya:
  - `heartbeat_interval` 10–240 (worker menandai agent offline setelah 300 detik).
  - `interval_minutes` ≥ 1.
  - `url` harus https.
  - enum `etw.mode` dan `firewall.backend`.
- Kolom/field agent baru `config_version` dan `config_error` diisi dari
  heartbeat.
- PoliciesPage mendapat bagian "Agent config" yang dikelompokkan per modul.
  - Field kosong menampilkan placeholder "pakai nilai lokal".
  - Ada catatan bahwa menyimpan perubahan akan merestart agent di group itu
    (sekitar 10 detik).
  - Ada peringatan khusus untuk `server.url`.
- Halaman Agents menampilkan status config per agent: diterapkan, pending,
  atau error beserta pesannya.

### Bonus: ACL `C:\ProgramData\SIEMAgent`

`restrictConfigAccess` hanya berjalan saat MSI `-configure`. Kalau seseorang
menambahkan ACE (mis. tombol "Continue" di Explorer menambahkan akun admin
yang sedang login dengan Full Control), ACE itu bertahan selamanya. Agent
sebaiknya memasang ulang ACL SYSTEM+Administrators setiap kali service start
di Windows.

## Untuk builder

- Bentuk persis struct overlay di Go (pointer per field untuk membedakan
  "tidak diisi" dari nilai nol) dan di pydantic.
- Cara membandingkan config efektif (mis. hash dari overlay yang dinormalisasi).
- Migrasi Alembic untuk kolom status agent.
- Tata letak form di PoliciesPage.

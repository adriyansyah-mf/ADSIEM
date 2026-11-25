# Agent Config dari Dashboard — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operator mengatur setting operasional `config.yaml` agent per group
dari halaman Policies. Agent menumpuknya ke config lokal lalu restart sendiri.

**Architecture:**
- `PolicySettings` mendapat `agent_config` (overlay, semua field opsional).
  Server memberi overlay itu versi tersendiri (`config_version`) di policy
  yang diambil agent.
- Agent menerapkan overlay saat boot, sebelum modul dibuat. Kalau versi
  berubah, agent shutdown dengan rapi lalu keluar dengan kode 3 supaya
  SCM/systemd menyalakannya lagi.
- Status (`config_version`, `config_error`) dikirim lewat heartbeat dan
  ditampilkan di halaman Agents.

**Tech Stack:** Go (agent), FastAPI + pydantic + SQLAlchemy async (server-api), React + TanStack Query (dashboard).

**Spec:** `docs/superpowers/specs/2026-11-25-agent-config-dashboard-design.md`

## Global Constraints

- Whitelist ditegakkan di agent. Struct Go `config.Overlay` **hanya** memuat
  field whitelist, sehingga field lain dari server tidak pernah ter-decode.
- Penyimpangan dari spec: `logs` dan `fim.watch_paths` **tidak** masuk
  overlay. Keduanya sudah dikelola per agent dari server lewat heartbeat
  (`mgr.Update(resp.LogSources)`, `fimWatcher.UpdatePaths(resp.FimPaths)` di
  `agent/cmd/agent/main.go`).
- Field yang tetap lokal:
  - `agent.id/name/group`, `token`, `enrollment_token`, `state_dir`,
    `config_path`, `config_version`.
  - `live_response.*`, `anti_tamper.*`, `update.trusted_keys`.
  - `buffer.spill_path`, `firewall.state_path`, `evidence.dir`.
- `server.url` dari overlay hanya diterima kalau host-nya (hostname,
  case-insensitive) sama dengan URL di `config.yaml`, dan skemanya `https`.
  Kalau tidak, field itu diabaikan, field lain tetap diterapkan, dan
  `config_error` diisi.
- Crash guard: 3 kali start dalam 10 menit dengan versi yang sama tanpa
  pernah sehat → versi itu ditolak dan agent boot dengan config lokal.
- Fallback URL: kalau tidak ada kontak sukses ke server selama 10 menit
  dengan URL dari overlay, versi itu ditolak dan agent restart ke URL lokal.
- Restart memakai jitter acak 0–60 detik. Kode keluar 3, dan **tidak** melapor
  `SERVICE_STOPPED`.
- Kalau agent tidak berjalan di bawah service manager, jangan keluar. Log
  "restart required" dan isi `config_error`.
- Validasi server:
  - `heartbeat_interval` 10–3600.
  - `memory_sweep.interval_minutes` 1–1440.
  - `yara.max_file_size_mb` 1–1024.
  - `etw.mode` ∈ {auto,on,off}.
  - `firewall.backend` ∈ nilai yang diterima `agent/internal/firewall` (baca
    di sana).
  - `url` harus https.
- Commit:
  - Jalankan `git -c user.name=adriyansyah-mf -c user.email=adriyansyahmf0@gmail.com commit`
    dengan trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  - **Jangan** stage `.claude/settings.json`,
    `agent/internal/yara/builtin_test.go` (terhapus), atau `~/`.
- Go: pakai `go` di PATH, atau toolchain di scratchpad
  (`gotc/go/bin/go.exe`, `GOTOOLCHAIN=local`). Jalankan dari `agent/`.

## Review Focus

1. **Policy lama tanpa `agent_config`** (agent baru, server lama, atau
   sebaliknya): agent harus boot dengan config lokal persis seperti sekarang
   dan tidak pernah restart. Test ada di Task 3.
2. **Overlay berisi field nol eksplisit** (`enabled: false`, list kosong
   `[]`): ini harus menimpa nilai lokal. Beda dengan field yang tidak diisi.
   Test ada di Task 1.
3. **Setelah restart karena config, server mengirim versi yang sama lagi:**
   agent tidak boleh restart kedua kalinya. Test ada di Task 3.
4. **`config.Watch` mengubah `server.url` lokal sementara overlay mengisi
   URL:** URL overlay tetap dipakai. Kalau overlay tidak mengisi URL,
   hot-reload berjalan seperti sekarang. Test ada di Task 4.
5. **Server menolak overlay tidak valid dengan 422**, bukan menyimpannya lalu
   membuat seluruh fleet crash. Test ada di Task 5.

---

### Task 1: `config.Overlay` dan `ApplyOverlay`

**Files:**
- Create: `agent/internal/config/overlay.go`
- Test: `agent/internal/config/overlay_test.go`

**Interfaces:**
- Produces:
  - `type Overlay struct`, dengan bagian pointer `Server *ServerOverlay`,
    `Agent *AgentOverlay`, `FIM`, `Firewall`, `Netwatch`, `ETW`, `Detect`,
    `LinuxSensor`, `Ransomware`, `Yara`, `MemorySweep`, `Evidence`,
    `Prevention`, `Notify`, `ProjectScan`, `Update`. JSON tag snake_case
    sama dengan yaml (`server`, `linux_sensor`, `memory_sweep`, …).
  - Setiap field skalar adalah pointer (`*bool`, `*int`, `*string`,
    `*int64`). Setiap list adalah `*[]string`, supaya `[]` eksplisit berbeda
    dari "tidak diisi".
  - Field per bagian persis seperti tabel whitelist di spec, minus `logs` dan
    `fim.watch_paths`.
  - `func ApplyOverlay(cfg *Config, o *Overlay) (warnings []string)`
    menulis setiap field non-nil ke cfg. `o == nil` tidak melakukan apa-apa.
    `server.url` dengan host berbeda atau bukan https diabaikan, dengan
    warning `"server.url: host must stay <host>"`.

- [ ] **Step 1: Tulis test yang gagal**

```go
func TestApplyOverlayNilKeepsLocal(t *testing.T) {
	cfg := &Config{FIM: FimConfig{Enabled: true}}
	if w := ApplyOverlay(cfg, nil); len(w) != 0 || !cfg.FIM.Enabled { t.Fatal(w, cfg.FIM) }
}
func TestApplyOverlayExplicitZeroOverrides(t *testing.T) {
	cfg := &Config{FIM: FimConfig{Enabled: true}, Yara: YaraConfig{WatchPaths: []string{`C:\x`}}}
	var o Overlay
	json.Unmarshal([]byte(`{"fim":{"enabled":false},"yara":{"watch_paths":[]}}`), &o)
	ApplyOverlay(cfg, &o)
	if cfg.FIM.Enabled || len(cfg.Yara.WatchPaths) != 0 { t.Fatal(cfg.FIM, cfg.Yara) }
}
func TestApplyOverlayURLSameHostOnly(t *testing.T) {
	cfg := &Config{Server: ServerConfig{URL: "https://Siem.example.com"}}
	var o Overlay
	json.Unmarshal([]byte(`{"server":{"url":"https://siem.example.com:8443/x"}}`), &o)
	if w := ApplyOverlay(cfg, &o); len(w) != 0 || cfg.Server.URL != "https://siem.example.com:8443/x" { t.Fatal(w, cfg.Server.URL) }
	json.Unmarshal([]byte(`{"server":{"url":"https://evil.example.net"}}`), &o)
	if w := ApplyOverlay(cfg, &o); len(w) != 1 || cfg.Server.URL != "https://siem.example.com:8443/x" { t.Fatal(w, cfg.Server.URL) }
}
func TestOverlayIgnoresUnlistedFields(t *testing.T) {
	cfg := &Config{AntiTamper: AntiTamperConfig{UnlockService: false}, Agent: AgentConfig{Token: "t"}}
	var o Overlay
	json.Unmarshal([]byte(`{"anti_tamper":{"unlock_service":true},"agent":{"token":"x","buffer_size":5}}`), &o)
	ApplyOverlay(cfg, &o)
	if cfg.AntiTamper.UnlockService || cfg.Agent.Token != "t" || cfg.Agent.BufferSize != 5 { t.Fatal(cfg) }
}
```

- [ ] **Step 2:** Jalankan `go test ./internal/config/ -run Overlay`.
  Expected: FAIL (undefined `Overlay`).
- [ ] **Step 3:** Implementasikan `overlay.go`. Bandingkan host dengan
  `url.Parse(...).Hostname()` lewat `strings.EqualFold`, terhadap URL di cfg
  **sebelum** overlay diterapkan.
- [ ] **Step 4:** Jalankan `go test ./internal/config/`. Expected: PASS.
- [ ] **Step 5:** Commit dengan pesan `feat(agent): config overlay with a field whitelist`.

### Task 2: Policy membawa overlay dan versinya

**Files:**
- Modify: `agent/internal/policy/policy.go`, bagian struct `Settings` dan `Policy`.
- Test: `agent/internal/policy/policy_test.go` (tambahkan).

**Interfaces:**
- Consumes: `config.Overlay` (Task 1).
- Produces:
  - `Settings.AgentConfig *config.Overlay`, dengan tag
    `json:"agent_config,omitempty"`.
  - `Policy.ConfigVersion string`, dengan tag
    `json:"config_version,omitempty"`. Ini versi overlay dari server
    (Task 5). `""` berarti tidak ada overlay.
  - `func Load(path string) *Policy`: membaca `policy.json` tanpa menyalakan
    store (untuk boot). Kalau file tidak ada atau rusak, kembalikan nil.
    Pakai lagi parser yang sudah dipakai `Open`.

- [ ] **Step 1:** Tulis test `TestPolicyAgentConfigRoundTrip`. Isinya: tulis
  `policy.json` dengan `{"config_version":"abc","settings":{"agent_config":{"fim":{"enabled":false}}}}`,
  lalu cek `Load(p).ConfigVersion == "abc"` dan
  `*Load(p).Settings.AgentConfig.FIM.Enabled == false`. Tambah juga
  `TestLoadMissing`: `Load` untuk file yang tidak ada mengembalikan nil.
- [ ] **Step 2:** Jalankan `go test ./internal/policy/ -run 'AgentConfig|LoadMissing'`. Expected: FAIL.
- [ ] **Step 3:** Implementasikan. Pastikan tidak ada import cycle (`config` tidak boleh mengimpor `policy`).
- [ ] **Step 4:** Jalankan `go test ./internal/policy/ ./internal/config/`. Expected: PASS.
- [ ] **Step 5:** Commit dengan pesan `feat(agent): policy carries the agent config overlay`.

### Task 3: Paket `agentcfg`: boot, crash guard, keputusan restart, fallback URL

**Files:**
- Create: `agent/internal/agentcfg/agentcfg.go`
- Test: `agent/internal/agentcfg/agentcfg_test.go`

**Interfaces:**
- Consumes: `config.ApplyOverlay`, `policy.Policy` (Tasks 1–2).
- Produces:
  - State file `agent_config_state.json` di state dir:
    `{"version","starts":[unix…],"healthy":bool,"rejected":[version…],"restart_for":version}`.
  - `type Runtime struct` dengan `Now func() time.Time` yang bisa diganti di test.
  - `func Boot(cfg *config.Config, stateDir string, p *policy.Policy) *Runtime`.
    - Dipanggil sebelum modul dibuat.
    - Kalau `p == nil`, `ConfigVersion == ""`, versinya ada di `rejected`, atau
      ada ≥3 `starts` dalam 10 menit terakhir untuk versi yang sama dengan
      `healthy == false`: jangan terapkan overlay. Pada kasus crash, tambahkan
      versi itu ke `rejected` dan set error
      `"config <v> rejected: agent kept failing to start"`.
    - Selain itu panggil `ApplyOverlay`. Warning-nya menjadi error.
    - Catat start baru, simpan state.
  - `func (r *Runtime) Status() (version, errMsg string)`. `version` adalah
    versi yang benar-benar berjalan (`""` kalau tidak ada overlay).
  - `func (r *Runtime) MarkHealthy()`. Set `healthy = true` dan kosongkan
    `starts`. Dipanggil setelah 10 menit uptime.
  - `func (r *Runtime) Want(p *policy.Policy, probe func(url string) error) (restart bool)`.
    - Kembalikan false kalau versi sama dengan yang berjalan, versinya ditolak,
      atau `restart_for == versi`. Kasus terakhir diberi error
      `"config <v> still differs after restart"`.
    - Kalau overlay baru mengganti `server.url`, jalankan `probe(newURL)`. Kalau
      gagal, tolak versi itu dengan error `"server.url <u> unreachable: <err>"`
      dan kembalikan false.
    - Selain itu set `restart_for = versi`, simpan state, kembalikan true.
  - `func (r *Runtime) CheckContact(lastOK time.Time) (restart bool)`.
    Kalau URL yang berjalan berasal dari overlay dan
    `Now() - max(bootTime, lastOK) > 10m`: tolak versi itu dan kembalikan
    true. Setelah restart, `Boot` tidak akan menerapkan versi itu lagi.

- [ ] **Step 1:** Tulis test-test berikut (temp dir, `Now` palsu):
  - `TestBootNoPolicyIsLocal`
  - `TestBootAppliesOverlay`
  - `TestBootRejectsAfterThreeFailedStarts`: Boot 3× dalam 5 menit tanpa
    `MarkHealthy`. Boot ke-4 → cfg lokal, `Status().errMsg` berisi
    "kept failing".
  - `TestBootHealthyResetsCrashCount`
  - `TestWantSameVersionNoRestart`
  - `TestWantNewVersionRestartsOnce`: true, lalu Boot dengan versi itu yang
    tetap berbeda karena dimanipulasi → `Want` false.
  - `TestWantURLProbeFailureRejects`
  - `TestCheckContactRevertsAfter10m`
  - `TestCheckContactIgnoresLocalURL`
- [ ] **Step 2:** Jalankan `go test ./internal/agentcfg/`. Expected: FAIL (package tidak ada).
- [ ] **Step 3:** Implementasikan. Penulisan state dibuat atomik (tulis file tmp, lalu rename).
- [ ] **Step 4:** Jalankan `go test ./internal/agentcfg/`. Expected: PASS.
- [ ] **Step 5:** Commit dengan pesan `feat(agent): apply, guard and roll back the dashboard config`.

### Task 4: Wiring agent: boot, restart, heartbeat, Watch, ACL

**Files:**
- Modify: `agent/cmd/agent/main.go`:
  - `run()`, setelah token di-load (~baris 225) dan sebelum `client.New`.
  - Callback `config.Watch` (~baris 320).
  - Callback heartbeat (~baris 835).
  - Penantian `<-stop` (~baris 899).
- Create: `agent/cmd/agent/restart.go`, berisi
  `func restartAfter(stop chan<- struct{}, d time.Duration)` dan
  `var restartRequested atomic.Bool`.
- Modify: `agent/cmd/agent/service_windows.go` dan `service_other.go`:
  tambahkan `func underServiceManager() bool`.
  - Windows: `svc.IsWindowsService()`.
  - Lainnya: `os.Getenv("INVOCATION_ID") != ""` (systemd).
- Modify: `agent/internal/heartbeat/heartbeat.go`.
  - Tambahkan ke `HeartbeatRequest`: `ConfigVersion string json:"config_version,omitempty"`
    dan `ConfigError string json:"config_error,omitempty"`.
  - Tambahkan hook paket `var ConfigStatus func() (string, string)`, mirip
    `EvidenceHealth`.
  - Tambahkan `var LastOK atomic.Int64` (unix), di-set setiap heartbeat
    sukses. Kalau sudah ada penanda sejenis, pakai yang itu.
- Modify: `agent/cmd/agent/configure_windows.go`. Ekspor pemanggilan ulang
  ACL: `run()` memanggil `restrictConfigAccess(configPath)` saat start di
  Windows. Di platform lain `chmod 0600` yang sudah ada sudah setara.
- Test: `agent/cmd/agent/restart_test.go`.

**Interfaces:**
- Consumes: `agentcfg.Boot/Want/CheckContact/MarkHealthy/Status`, `policy.Load`.

Urutan di `run()`:
1. `rt := agentcfg.Boot(cfg, task.StateDir(cfg), policy.Load(<policy path>))`.
   Ini sebelum `client.New`, buffer, dan modul.
2. `heartbeat.ConfigStatus = rt.Status`.
3. `polStore.OnChange(func(p){ if rt.Want(p, probe) { go restartAfter(internalStop, jitter) } })`.
   - `probe(u)` = GET `policy.Path` ke `u` dengan token agent, timeout
     15 detik, TLS terverifikasi.
   - Jangan pakai heartbeat sebagai probe: server memperlakukan dua sesi
     heartbeat sebagai token dipakai ganda.
   - `jitter` = acak 0–60 detik.
4. Goroutine tiap menit:
   - `rt.CheckContact(time.Unix(heartbeat.LastOK.Load(),0))` → restart.
   - Setelah 10 menit uptime, `rt.MarkHealthy()` sekali.
5. Callback Watch: `cfg.Server.URL`/`c.BaseURL` hanya diubah kalau overlay
   yang berjalan tidak mengisi `server.url`. Ekspos
   `rt.OverlaySetsURL() bool`, tambahan kecil di Task 3.
6. Penantian akhir berubah dari `<-stop` menjadi
   `select { case <-stop: case <-internalStop: }`. Jalur shutdown yang ada
   tetap dipakai (flush buffer).
   - Kalau `restartRequested` dan `underServiceManager()`: setelah shutdown
     selesai, `os.Exit(3)` dari dalam `run()`, sebelum handler svc melapor
     `STOPPED`. Dengan begitu SCM menjalankan recovery action.
   - Kalau tidak di bawah service manager: `restartAfter` tidak menutup stop.
     Ia hanya log `"config changed: restart required"`.

- [ ] **Step 1:** Tulis test berikut:
  - `TestRestartAfterNotUnderManagerOnlyLogs`: `underServiceManager` bisa
    diganti lewat variabel fungsi. Channel tidak tertutup dan
    `restartRequested == false`.
  - `TestRestartAfterUnderManagerCloses`
- [ ] **Step 2:** Jalankan `go test ./cmd/agent/ -run RestartAfter`. Expected: FAIL.
- [ ] **Step 3:** Implementasikan semua wiring di atas.
- [ ] **Step 4:** Jalankan semuanya:
  - `go test ./internal/config/ ./internal/policy/ ./internal/agentcfg/ ./internal/heartbeat/ ./cmd/agent/`
  - `go vet ./...`
  - `GOOS=linux go build ./...`
  - `GOOS=windows go build ./...`

  Expected: semua PASS atau build OK.
- [ ] **Step 5:** Commit dengan pesan `feat(agent): restart into the dashboard config and report its status`.

### Task 5: Server: model overlay, versi, status heartbeat

**Files:**
- Create: `server-api/app/services/agent_config.py`, berisi model pydantic
  `AgentConfigOverlay` dan `config_version_of(overlay: dict | None) -> str`.
- Modify: `server-api/app/services/agent_policy.py`.
  - `PolicySettings.agent_config: AgentConfigOverlay | None = None`.
  - `effective()` menambahkan `"config_version"`.
  - `for_agent()` meneruskan `config_version` di top level.
- Modify: `server-api/app/schemas/schemas.py`.
  - `HeartbeatRequest`: `config_version: str | None = Field(None, max_length=64)`
    dan `config_error: str | None = Field(None, max_length=500)`.
  - Schema output agent: `config_version`, `config_error`, `config_expected`.
- Modify: `server-api/app/models/models.py`, model `Agent`:
  - `config_version = Column(String(64))`
  - `config_error = Column(Text)`
- Modify: `server-api/app/main.py`. Tambahkan `_migrate_agent_config_status()`
  dengan pola `_migrate_agent_sensor_health` (`ALTER TABLE agents ADD COLUMN IF NOT EXISTS …`),
  lalu panggil dari lifespan.
- Modify: `server-api/app/api/routes/ingest.py` (heartbeat). Simpan
  `config_version`/`config_error` kalau dikirim (pola `sensor_health`, ~baris 304).
- Modify: route list/detail agent (cari schema output agent). Isi
  `config_expected = (await agent_policy.effective(db, a.group_id))["config_version"]`.
  `effective` sudah di-cache 30 detik per group.
- Test:
  - Create `tests/server-api/test_agent_config.py` (unit, tanpa DB).
  - Tambahkan ke `tests/server-api/test_agent_policy.int.py`.

**Interfaces:**
- Produces:
  - `config_version_of(None) == ""`.
  - Selain itu `sha256(json.dumps(overlay_without_nones, sort_keys=True))[:16]`.
    Overlay di-dump dengan `exclude_none=True`, sehingga "tidak diisi" tidak
    pernah dikirim sebagai `null` ke agent.

- [ ] **Step 1:** Tulis test unit berikut:

```python
def test_empty_overlay_has_no_version():
    assert config_version_of(None) == "" and config_version_of({}) == ""
def test_version_ignores_unset_fields():
    a = AgentConfigOverlay.model_validate({"fim": {"enabled": False}}).model_dump(exclude_none=True)
    assert config_version_of(a) == config_version_of({"fim": {"enabled": False}})
@pytest.mark.parametrize("bad", [
    {"server": {"url": "http://siem.example.com"}},
    {"server": {"heartbeat_interval": 5}},
    {"memory_sweep": {"interval_minutes": 0}},
    {"etw": {"mode": "sometimes"}},
    {"anti_tamper": {"unlock_service": True}},   # extra="forbid"
    {"agent": {"token": "x"}},
])
def test_overlay_rejects(bad):
    with pytest.raises(ValidationError):
        AgentConfigOverlay.model_validate(bad)
```

  Lalu tambahkan ke test int policy:
  - `PUT /api/policies/<g>` dengan `agent_config` tidak valid → 422.
  - Overlay valid → `GET /api/ingest/policy` (agent) berisi `config_version`
    tidak kosong dan `settings.agent_config` tanpa `null`.
  - Heartbeat dengan `config_version`/`config_error` → tersimpan di baris agent.
  - Mengubah ML false positive mengubah `version` tetapi **tidak**
    `config_version`.
- [ ] **Step 2:** Jalankan `pytest tests/server-api/test_agent_config.py -v`. Expected: FAIL (import).
- [ ] **Step 3:** Implementasikan. Semua model overlay memakai
  `model_config = ConfigDict(extra="forbid")`.
- [ ] **Step 4:** Jalankan `pytest tests/server-api/test_agent_config.py tests/server-api/test_agent_policy.int.py -v`
  (test int memerlukan Postgres seperti suite yang ada). Expected: PASS.
- [ ] **Step 5:** Commit dengan pesan `feat(server): agent config overlay in group policy with applied status`.

### Task 6: Dashboard: form Agent config dan status per agent

**Files:**
- Create: `dashboard/src/pages/policies/AgentConfigEditor.tsx`, berisi
  `export function AgentConfigEditor({ value, onChange }: { value: AgentConfig | null; onChange: (v: AgentConfig | null) => void })`.
- Modify: `dashboard/src/pages/PoliciesPage.tsx`.
  - Interface `Settings` mendapat `agent_config?: AgentConfig | null`.
  - Render `AgentConfigEditor` di `Editor`, di bawah setting yang sudah ada.
- Modify: `dashboard/src/types/index.ts`.
  - Tipe `AgentConfig`, yang mencerminkan `AgentConfigOverlay` dengan semua
    field opsional.
  - `Agent` mendapat `config_version`, `config_error`, `config_expected`.
- Modify: `dashboard/src/pages/AgentsPage.tsx`. Tambahkan badge status config:
  - **diterapkan:** `config_version === config_expected`, tanpa error.
  - **pending:** versi beda, tanpa error.
  - **error:** ada `config_error`. Tooltip berisi pesannya.

Perilaku form (sesuai spec):
- Dikelompokkan per bagian (Server, Firewall, ETW, Detect, YARA, Ransomware,
  Memory sweep, Evidence, Modul lain).
- Field kosong → `undefined`, dengan placeholder "pakai nilai lokal".
- Checkbox tiga keadaan untuk bool: lokal / on / off.
- List diisi satu item per baris. Textarea kosong berarti "lokal", dengan
  opsi eksplisit "kosongkan".
- Ada banner tetap: "Menyimpan perubahan merestart agent di group ini
  (±10 detik, dengan jeda acak hingga 1 menit)."
- Di field URL ada catatan: "Hanya port/path di host yang sama. Pindah host
  lewat config.yaml lokal."
- Ada catatan: "Group dengan policy sendiri tidak mewarisi Agent config dari
  default."
- Semua bagian kosong → kirim `agent_config: null`.

- [ ] **Step 1:** Jalankan `npm --prefix dashboard run build` untuk baseline. Expected: OK.
- [ ] **Step 2:** Implementasikan.
- [ ] **Step 3:** Jalankan `npm --prefix dashboard run build` dan `npm --prefix dashboard run lint` (kalau ada). Expected: OK tanpa error tipe.
- [ ] **Step 4:** Commit dengan pesan `feat(dashboard): agent config per group and applied status`.

### Task 7: Dokumentasi operasi

**Files:**
- Modify: `agent/packaging/windows/config.yaml` dan `agent/packaging/config.yaml`
  (kalau ada). Tambahkan komentar di atas setiap bagian whitelist: "dapat
  ditimpa dari dashboard (Policies → Agent config)".
- Create: `docs/operations/agent-config-dashboard.md`. Isinya:
  - field mana yang bisa diatur dan mana yang tetap lokal;
  - perilaku restart;
  - crash guard dan fallback URL;
  - cara membaca status di halaman Agents;
  - bahwa ACL folder data dipasang ulang setiap start.

- [ ] **Step 1:** Tulis keduanya.
- [ ] **Step 2:** Commit dengan pesan `docs: agent config from the dashboard`.

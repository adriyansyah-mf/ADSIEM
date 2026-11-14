# OT / ICS detection (Modbus, DNP3)

PLCs, RTUs, IEDs and protective relays can't run an agent, so ADSIEM watches
them from the network. A Suricata sensor on a mirror (SPAN) port of the OT
segment parses Modbus/TCP and DNP3. ADSIEM decodes each transaction's function
code and alerts on the operations that change, stop or map the process. The
agent still covers the Windows/Linux hosts around the process: the HMI,
SCADA server, historian and engineering workstation.

```
PLC / RTU ◀─── Modbus 502 / DNP3 20000 ───▶ HMI, SCADA master, engineering workstation
                     │ SPAN / TAP
                     ▼
              Suricata sensor ── eve.json ──▶ rsyslog ──TCP 514──▶ ADSIEM syslog receiver
                                              (or the agent tails eve.json)
                                                         │
                     decoders/suricata_eve_{modbus,dnp3}.yaml → rules/ot_*.yaml → alert → AI triage / case
```

## 1. Suricata

In `suricata.yaml`, enable both parsers and their EVE loggers. Modbus is off
by default. Check that your version writes `event_type: modbus` and `dnp3`
records (`tail -f eve.json | grep -E '"event_type":"(modbus|dnp3)"'`); Suricata
7 does.

```yaml
app-layer:
  protocols:
    modbus:
      enabled: yes
      detection-ports:
        dp: 502
    dnp3:
      enabled: yes
      detection-ports:
        dp: 20000

outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert
        - flow
        - modbus
        - dnp3
```

Add the ICS signatures, for example Emerging Threats' `emerging-scada.rules`
(`suricata-update enable-source et/open`). Their alerts are raised as high by
"Suricata ICS/SCADA Signature Alert", whatever their own priority.

## 2. Getting eve.json to ADSIEM

Choose one:

- **Syslog (no agent on the sensor):** forward with rsyslog
  (`/etc/rsyslog.d/91-suricata.conf`), then register the sensor's address
  under **Environment → Syslog devices** with log type `suricata`.

  ```
  module(load="imfile")
  input(type="imfile" File="/var/log/suricata/eve.json" Tag="suricata" Severity="info")
  if $programname == 'suricata' then @@<siem-host>:514
  ```

- **Agent:** add `/var/log/suricata/eve.json` as a log source with type
  `suricata`.

## 3. What is decoded

| Field | Modbus | DNP3 |
|---|---|---|
| `ot.protocol` | `modbus` | `dnp3` |
| `ot.function_code` | request function (`function_raw`, a number) | application function code |
| `ot.function_name` | Suricata's name for it (varies by version) | — |
| `ot.unit_id` | unit (slave) ID | — |
| `ot.subfunction` | diagnostics sub-function / MEI type | — |
| `ot.address`, `ot.quantity` | register/coil address and count | — |
| `ot.exception`, `ot.exception_name` | exception code in the response | — |
| `ot.message_type` | — | `request` / `response` |
| `ot.source_address`, `ot.destination_address` | — | DNP3 link addresses |

Suricata's own fields stay on the event too (`modbus.request.*`, `dnp3.*`), as
do `source.ip`, `destination.ip`, ports and `observer.hostname` (the sensor).
Rules use the function code *number*, because Suricata's names for function
codes differ between versions.

## 4. Rules

All ship enabled and need no site addresses. Tags are MITRE ATT&CK for ICS.

| Rule (`rules/`) | Level | When |
|---|---|---|
| `ot_control_command_from_internet` | critical | Modbus 5/6/15/16/22/23 or DNP3 write, select/operate, direct operate, restart, stop or disable unsolicited, from a non-RFC1918 address |
| `ot_modbus_plc_programming` | critical | Modbus 90 (Schneider UMAS: stop/start PLC, read/download program) |
| `ot_dnp3_restart_or_stop` | critical | DNP3 13 cold restart, 14 warm restart, 15 initialize data, 16 initialize application, 18 stop application |
| `ot_service_exposed_to_internet` | high | any record from a public address to 502, 20000, 102, 2404, 44818, 47808, 1911, 4911, 9600, 18245, 18246 |
| `ot_modbus_scan`: Function Code Scan | high | ≥ 6 distinct function codes, one source → one device, 5 min |
| `ot_modbus_scan`: Unit ID Sweep | high | ≥ 10 distinct unit IDs, one source → one device, 5 min |
| `ot_modbus_diagnostics_dos` | high | Modbus 8 with sub-function 1 (restart comms), 4 (force listen-only), 10 (clear counters) |
| `ot_modbus_user_defined_function` | high | Modbus 65–72, 100–110 |
| `ot_dnp3_disable_unsolicited` | high | DNP3 21 |
| `ot_dnp3_file_delete` | high | DNP3 27 |
| `ot_ics_ids_signature` | high | Suricata alert whose signature or category names SCADA/ICS, Modbus, DNP3, S7, IEC 104, BACnet, EtherNet/IP, CIP, PROFINET, PLC |
| `ot_modbus_device_fingerprint` | medium | Modbus 43/14 (read device identification), 17 (report server ID) |

Each rule suppresses repeats per source and destination (15 min to 24 h), so a
polling loop raises one alert, not thousands. Alerts go through the usual
pipeline: AI triage, case grouping by IOC (the attacker's address ties the
steps into one case), AI Investigate, and SOAR.

**Per-site rules.** "A write from anything but our HMIs" needs your
addresses, so add it in the dashboard; see the example in the README
(*Syslog, Suricata, Zeek and OT*). Use the same pattern for maintenance
windows: exclude the engineering workstation for the hours of planned work.

## 5. Demo

`scripts/ot-demo-replay.py` (standard library only) replays an attack as
Suricata would log it. The target is the Modbus PLC that runs a fuel depot's
pumps and the DNP3 RTU of the substation that feeds it. Routine HMI polling
is mixed in and raises nothing.

| Step | Alert |
|---|---|
| internet scanner reaches the PLC's port 502 | OT Service Reached From The Internet |
| engineering workstation reads the PLC's identity | Modbus Device Identification Query |
| …tries 8 function codes | Modbus Function Code Scan |
| …sweeps 12 unit IDs | Modbus Unit ID Sweep |
| UMAS stop PLC / program download | Modbus PLC Programming Command (UMAS) |
| force listen-only | Modbus Diagnostics Restart Or Listen-Only Command |
| DNP3 disable unsolicited on the RTU | DNP3 Unsolicited Reporting Disabled |
| DNP3 cold restart, stop application | DNP3 Outstation Restart Or Stop Command |
| DNP3 delete file | DNP3 File Deleted On Outstation |
| pump setpoint writes from an internet address | OT Control Command From The Internet |

```
# 1. register the host you run it from: Environment → Syslog devices → <its IP>, log type "suricata"
# 2. replay (UDP 514 by default; --tcp, --port, --delay seconds between steps)
python3 scripts/ot-demo-replay.py --host <siem-host> --delay 2

# or feed an agent that tails a Suricata eve.json
python3 scripts/ot-demo-replay.py --print >> /var/log/suricata/eve.json
```

`tests/worker/test_ot_ics_rules.py` runs the same scenario through the real
decoders and rules. It checks that exactly these ten alerts are raised and
that the routine steps stay quiet.

# Troubleshooting

Issues found during the build, how each was investigated, and how it was resolved. Status labels are defined in the [README](../README.md#evidence-status-legend). Investigation details come from the operator's implementation notes (**Reported**) unless a stored capture is cited (**Verified**).

## TS-01: Wazuh manager not listening on TCP 1514

**Status: root cause verified.** An unclean VM shutdown left stale PID files. At the next boot, the start script mistook unrelated live processes for `wazuh-remoted` and `wazuh-syscheckd` and skipped starting both. The manager ran for ~24 minutes without its agent listener or its file-integrity monitor, and nothing alerted.

### Summary timeline (UTC)

| Time | Event | Source | Status |
|---|---|---|---|
| 11-08 18:25:57–58 | Boot. `wazuh-remoted` starts as **PID 1245** | journal, `ossec.log` | **Verified** |
| 11-08 → 11-09 | Wazuh VM stopped **without a clean shutdown**: at the next boot, every manager daemon still had a PID file | journal | **Verified** |
| 11-09 09:57:22–25 | Boot. The start script discards stale PID files whose PIDs are dead, then starts `wazuh-apid`, `wazuh-authd`, `wazuh-db`, `wazuh-execd`, `wazuh-analysisd` | journal | **Verified** |
| 11-09 09:57:26 | Stale `wazuh-syscheckd-1230.pid` and `wazuh-remoted-1245.pid` point at **live** processes, so the script prints `wazuh-syscheckd already running...` / `wazuh-remoted already running...` and **skips both** | journal | **Verified** |
| 11-09 09:57 → 10:21 | No listener on 1514, so agents cannot connect. No FIM on the Wazuh server. `wazuh-authd` (1515) works | operator, `ossec.log` | Partly **Verified** |
| 11-09 10:17:44–10:19:46 | Agents fall back to enrollment and are rejected as duplicates | `ossec.log` | **Verified** |
| 11-09 10:20:18 | `systemctl stop`: the script prints `Killing wazuh-remoted...` for a daemon that was never running | journal | **Verified** |
| 11-09 10:20:19 | Stop routine removes `wazuh-remoted` PID 1245 and `wazuh-syscheckd` PID 1230 files as `not used by Wazuh` | journal | **Verified** |
| 11-09 10:21:03–04 | `systemctl start`: FIM scan starts; `wazuh-remoted` starts (pid 4100), listening on 1514/TCP | `ossec.log` | **Verified** |

Evidence: [`wazuh-control-pstatus-and-journal.txt`](../evidence/wazuh/wazuh-control-pstatus-and-journal.txt), [`ossec-log-remoted-history.txt`](../evidence/wazuh/ossec-log-remoted-history.txt), [`ossec-log-excerpt-2026-11-09.txt`](../evidence/wazuh/ossec-log-excerpt-2026-11-09.txt), [`server-status.txt`](../evidence/wazuh/server-status.txt).

### Symptom

| Observation | Status |
|---|---|
| `wazuh-manager` service active | **Reported** |
| TCP 1515 (`wazuh-authd`) listening | **Reported** |
| TCP 1514 **not** listening | **Reported** |
| `pgrep -a wazuh-remoted` returned no process | **Reported** |
| Start-up reported `wazuh-remoted already running...` | **Verified** (journal, 09:57:26). It is printed by `wazuh-control` to the systemd journal, which is why it never appears in `ossec.log` |
| Agents repeatedly asking `wazuh-authd` (1515) to re-enroll and being rejected, 10:17:44–10:19:46 | **Verified** (`ossec.log`) |
| `<remote>` block present: `secure` / `1514` / `tcp` / `queue_size 131072` | **Verified** in current config ([manager config](../evidence/wazuh/wazuh-server-ossec.conf)) |

The manager was up, enrollment worked, and the listener was correctly configured, yet the daemon that owns port 1514 did not exist while start-up claimed it was running. That contradiction pointed the investigation at runtime state rather than configuration.

### Investigation

```bash
pgrep -a wazuh-remoted          # no output
```

The runtime directory held two PID files for `wazuh-remoted`:

```text
/var/ossec/var/run/wazuh-remoted-1245.pid
/var/ossec/var/run/wazuh-remoted-1305.pid
```

| PID file | Process holding that PID at the time | Status |
|---|---|---|
| `wazuh-remoted-1245.pid` | **`wazuh-db`**, a different Wazuh daemon | **Reported**. Plausible: `wazuh-db` was started one second before the remoted check (journal) |
| `wazuh-remoted-1305.pid` | none | **Reported**, origin unexplained (see below) |

Wazuh daemons name their PID files `<daemon>-<pid>.pid`. The commands used to map PID 1245 to `wazuh-db` were not recorded.

### How the start script decides a daemon is running (verified)

From the installed `/var/ossec/bin/wazuh-control` (lines 468–493):

```sh
for pid in `cat ${DIR}/var/run/${pfile}-*.pid 2>/dev/null`; do
    ps -p ${pid} > /dev/null 2>&1
    if [ ! $? = 0 ]; then
        echo "${pfile}: Process ${pid} not used by Wazuh, removing..."
        rm -f ${DIR}/var/run/${pfile}-${pid}.pid
        continue;
    fi
    kill -0 ${pid} > /dev/null 2>&1
    if [ $? = 0 ]; then
        return 1;          # treated as "running"
    fi
done
```

`pstatus()` asks only **whether any process with that PID exists** (`ps -p`, `kill -0`). It never checks *which program* holds the PID. A stale PID file is therefore harmless while its PID is unused, because it gets cleaned up. It becomes harmful when the kernel has handed that PID to any other process. The script then concludes the daemon is running and does not start it.

### History of `wazuh-remoted` before the failure

`ossec.log` ([`ossec-log-remoted-history.txt`](../evidence/wazuh/ossec-log-remoted-history.txt)) and the journal together give:

| Time (UTC) | Event | Reading |
|---|---|---|
| 11-08 13:27:10 | `Started (pid: 60356)` | First start after installation |
| 11-08 13:31:34 | `SIGNAL [(15)-(Terminated)] Received` | A clean stop looks like this |
| 11-08 13:31:44 | `Started (pid: 64202)` | |
| 11-08 14:18:10 / 17:17:27 / 17:23:20 | `Started (pid: 1312 / 1265 / 1267)` | Boots |
| 11-08 18:16:52–18:17:03 | Journal: stale PID files removed for **all ten** daemons, including `wazuh-remoted` 1267 | The VM had been stopped uncleanly after the 17:23 boot. The stale files were harmless because no live process held those PIDs |
| 11-08 18:17:00 | Journal: `Started wazuh-remoted...` | No matching `Started (pid …)` line in `ossec.log`. That instance's fate is unknown |
| 11-08 18:25:57–58 | Journal `Started wazuh-remoted...`; `ossec.log` **`Started (pid: 1245)`** | The owner of `wazuh-remoted-1245.pid`. No stale-file messages at this boot |
| 11-08 18:47:35 / 19:14:38 | `Authentication file changed` | Agent keys added (19:14:38 follows the Windows MSI install at 19:13) |
| 11-08 19:15:15 | Key error from agent `002` | See [OBS-04](#obs-04-key-error-from-agent-002-right-after-enrollment-2026-11-08-191515-utc) |
| 11-09 09:57:26 | Journal: **`already running`** for syscheckd and remoted | The failure |

At boot, `wazuh-remoted` repeatedly received PIDs in a narrow low range (1312, 1265, 1267, 1245), as did the other daemons (journal: 1110–1388). The same services start in nearly the same order every boot, so **a PID file left from one boot is likely to name a live Wazuh daemon after the next**. Unclean shutdowns had happened before (the 18:16 boot cleaned up after one). That time the leftover PIDs happened to be free; on 11-09 two of them were not.

### Resolution

```bash
sudo systemctl stop wazuh-manager
sudo systemctl start wazuh-manager
```

| Outcome | Status |
|---|---|
| Stop routine printed `Killing wazuh-remoted...`, then deleted the stale `wazuh-remoted` (1245) and `wazuh-syscheckd` (1230) PID files once those PIDs were free | **Verified** (journal 10:20:18–19) |
| `wazuh-remoted` started 10:21:04, pid 4100, listening on 1514/TCP; FIM scan started 10:21:03 | **Verified** (`ossec.log`) |
| `wazuh-remoted` running, PID 4100 | **Verified** (`ss -lntp`) |
| Kali reaches `192.168.56.103:1514` (and 443, 1515) | **Verified** (`nc -zv`) |
| Agents `001` and `002` connected after recovery | **Verified** (`agent_control -l`: both Active) |

**Manual PID-file cleanup was not needed for the 1245 file.** The journal shows the stop routine removing it once `wazuh-db` had exited and PID 1245 was free. A note on the stop: `Killing wazuh-remoted...` means the script sent its stop signal to whatever held the PID in the stale file, PID 1245. That PID was free one second later. The capture does not show the stop function itself, so exactly which process received that signal is not verified.

**`wazuh-remoted-1305.pid` remains unexplained.** No journal line in the window mentions PID 1305, either as removed or as running. Its creation and removal are not in the captured evidence. The operator's first account mentioned cleaning up PID state, so it may have been removed by hand. The last journal line, complete in a later re-run, is only `Started wazuh-remoted...` (10:21:04) and does not mention it.

### Root cause

| # | Link | Status |
|---|---|---|
| 1 | `wazuh-remoted` ran as PID 1245 from 11-08 18:25:58 | **Verified** |
| 2 | The VM was later stopped without a clean shutdown, leaving PID files for every daemon | **Verified** (journal at 09:57) |
| 3 | At the 11-09 09:57 boot, PIDs 1245 and 1230 were held by processes started moments earlier (1245 by `wazuh-db` per the operator) | Live PIDs **Verified** (script output); holder of 1245 **Reported** |
| 4 | `pstatus()` treats any live PID as "daemon running" | **Verified** (installed script) |
| 5 | `wazuh-remoted` and `wazuh-syscheckd` reported "already running" and were not started | **Verified** (journal; no start in `ossec.log`) |
| 6 | Port 1514 closed ~23½ min (09:57:26–10:21:04) and agents forced into re-enrollment | **Verified** (`ossec.log`; open/closed state **Reported**) |
| 7 | `stop` freed the PIDs, the script removed the stale files, and `start` succeeded | **Verified** |

### Impact

- **No agent telemetry reached the manager for ~23½ minutes.** Agents could not hold a session on 1514. Whether their local buffers retained and later delivered those events was not evaluated.
- **File-integrity monitoring on the Wazuh server was off for the same period.** `wazuh-syscheckd` was skipped too. Nothing reported it. This was only found in the journal during this write-up.
- **The SIEM did not alert on its own failure.** The only traces were a line in the systemd journal and `wazuh-authd` duplicate-enrollment warnings in `ossec.log`.

### Prevention / detection

- **Shut the Wazuh VM down cleanly**: `sudo shutdown -h now` inside the guest, or VirtualBox *ACPI Shutdown*. Not *Power Off*, not closing the window with "Power off the machine", and not leaving it running while the host sleeps. This removes the precondition (link 2).
- **After every boot, check listeners and processes directly, not via `wazuh-control status`.** The status command in this script relies on the same `pstatus()` check, so it is expected to be fooled in the same way. That expectation is based on the script's structure; the `status` function itself was not captured. Reliable checks:

  ```bash
  sudo ss -lntp | grep -E ':(1514|1515)\b'
  pgrep -a 'wazuh-(remoted|syscheckd)'
  sudo journalctl -u wazuh-manager -b --no-pager | grep -i 'already running'
  ```

- **Detect it with Wazuh itself (planned).** The manager already collects its own `journald`. A custom rule on `wazuh-control` output containing `already running` would turn this failure into an alert. Whether boot-time journal lines are collected (they are written before `wazuh-logcollector` starts) needs testing ([roadmap](roadmap.md)).
- Watch for the symptom the manager *does* log: bursts of `wazuh-authd: … Duplicate name …, rejecting enrollment` from agents that were already enrolled.

### Evidence to capture if it recurs

- `ss -lntp` and `pgrep -a wazuh-remoted` output.
- `ls -l /var/ossec/var/run/` and `ps -p <pid> -o pid,comm` for each PID named in a `wazuh-*` PID file: this would confirm which process holds the PID.
- `sudo journalctl -u wazuh-manager -b --no-pager` for the affected boot.

## TS-02: Windows agent installation

**No installation issue is evidenced.** The captured msiexec verbose log ([excerpt](../evidence/windows/wazuh-agent-msi-install-excerpt.txt)) records a clean install of Wazuh Agent 4.14.10 on 2026-11-08 at 19:13 UTC: `Installation completed successfully`, status `0`, service `WazuhSvc` installed with automatic start.

That log covers one install run only, so it cannot rule out earlier failed attempts.

## TS-03: Host-only networking and ICMP to the Windows host

### Situation

| Item | Status |
|---|---|
| Host-only addressing: Windows `192.168.56.1/24` on adapter "Ethernet 2" (VirtualBox Host-Only Ethernet Adapter), Ubuntu `192.168.56.104/24`, Kali `192.168.56.105/24` | **Verified** ([ip-configuration.txt](../evidence/network/ip-configuration.txt)) |
| Kali could not ping the Windows host before the rule was added | **Reported** (implied by the fix; failed ping not captured) |
| Kali pings `192.168.56.1` successfully with the rule in place: 3/3 replies, TTL 128, ~0.5–1 ms | **Verified** ([connectivity-checks.txt](../evidence/kali/connectivity-checks.txt)) |

TCP traffic between the lab machines worked, but ICMP echo to the Windows host did not. Windows Defender Firewall blocks inbound ICMPv4 echo requests by default, and that default applies to the VirtualBox host-only adapter like any other interface.

### Resolution

A scoped inbound rule was created on the Windows host (elevated PowerShell, **Reported**):

```powershell
New-NetFirewallRule `
  -DisplayName "Wazuh Lab - Allow ICMPv4 Echo" `
  -Direction Inbound `
  -Protocol ICMPv4 `
  -IcmpType 8 `
  -Action Allow `
  -RemoteAddress 192.168.56.0/24 `
  -Profile Any
```

**Design choices:**
- `-IcmpType 8` allows echo request only, not every ICMP type.
- `-RemoteAddress 192.168.56.0/24` limits the exception to the lab subnet.
- `-Profile Any` makes the rule apply whichever network profile Windows assigns to the host-only adapter. The trade-off is that the rule also applies on other profiles, but the remote-address scope still confines it to `192.168.56.0/24` sources. If the physical LAN ever used that range the scope would not protect it; it currently does not (the Wi-Fi adapter is on a different subnet).

### Evidence to capture

The successful ping is captured. The rule definition itself is not yet captured, so it stays **Reported**:

```powershell
Get-NetFirewallRule -DisplayName "Wazuh Lab - Allow ICMPv4 Echo" |
  Format-List DisplayName, Enabled, Direction, Action, Profile
Get-NetFirewallRule -DisplayName "Wazuh Lab - Allow ICMPv4 Echo" | Get-NetFirewallAddressFilter
```

## Open observations from `ossec.log` (2026-11-08 and 11-09)

The same [`ossec.log` excerpt](../evidence/wazuh/ossec-log-excerpt-2026-11-09.txt) and the [`wazuh-remoted` history](../evidence/wazuh/ossec-log-remoted-history.txt) contain four events that are **not** part of TS-01. They are recorded here as open items. Their causes have not been investigated.

### OBS-01: Sysmon event rejected by the analysis engine (10:47:32 UTC)

```text
2026/11/09 10:47:32 wazuh-analysisd: WARNING: Could not read XML string: '"<Event xmlns=…>…[Sysmon EventID 1]…</Event>"'
```

The event was a Sysmon EID 1 from `windows-host`: `powershell.exe -NoProfile -NonInteractive -NoLogo -EncodedCommand <~16,000-character base64>`, launched by the **Claude Code desktop app** (the tool used to write this documentation) in `E:\Projects\WazuhHomelab`. The activity itself was benign tooling. The point is what happened to the event:

- `wazuh-analysisd` could not parse the event XML, so the event was **not decoded and could not match any rule**.
- The exact reason was not determined. The event was very large, and its `ParentCommandLine` field appears already truncated (`…`), which points towards a size limit somewhere in the collection path.
- **Detection impact:** a process creation with a very long command line, the shape of a large `-EncodedCommand` payload (T1027 / T1059.001), can fail decoding and silently produce no alert. This is worth testing deliberately (see [roadmap](roadmap.md) Phase 3).
- It also shows that legitimate developer tooling on the physical host generates `-EncodedCommand` PowerShell, which matters for tuning any rule keyed on that flag.

### OBS-02: "Agent key already in use: agent ID '002'" (11:36:43 UTC)

`wazuh-remoted` logged this warning 21 times within one second for the Windows agent. It typically appears when a connection arrives for an agent key that the manager still considers in use, for example a reconnect before the previous session was released, or two agent instances sharing one key. Which applies here was not determined. `agent_control -l` later showed `002` as Active.

### OBS-03: Indexer not ready after boot (13:21–13:22 UTC)

After the 13:21 start, `indexer-connector` logged `IndexerConnector initialization failed … retrying` for the `wazuh-states-*` indices, then `Failed to sync agent '001'` / `'002': No available server`. At 13:22:52 it reported `initialized successfully`. This is consistent with the manager starting before the indexer was ready on the same VM, and it resolved itself within about 65 s. No data loss was evaluated.

### OBS-04: Key error from agent 002 right after enrollment (2026-11-08 19:15:15 UTC)

```text
2026/11/08 19:14:38 wazuh-remoted: INFO: (1409): Authentication file changed. Updating.
2026/11/08 19:15:15 wazuh-remoted: WARNING: (1404): Authentication error. Wrong key or corrupt payload. Message received from agent '002' at 'any'.
2026/11/08 19:15:15 wazuh-remoted: WARNING: Decrypt the message fail, socket 30
```

About a minute after the Windows agent was installed (MSI, 19:13 UTC) and its key was added to the manager (19:14:38), the first message from agent `002` failed decryption. It was transient. By 19:39:44 the same agent was delivering Sysmon alerts ([raw alert](../evidence/wazuh/sysmon-eid1-alert-92027-raw.json)), and the agent configuration was last modified at 19:38. Whether an agent restart in between cleared it was not recorded. Cause not determined. Source: [`ossec-log-remoted-history.txt`](../evidence/wazuh/ossec-log-remoted-history.txt).

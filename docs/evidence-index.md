# Evidence Index

Every evidence file in this repository, what it shows, and what is still missing. Timestamps are converted to UTC (see [README](../README.md#time-zones-used-in-evidence)).

## Stored evidence

### Wazuh server (`evidence/wazuh/`)

| ID | File | What it shows | Limits |
|---|---|---|---|
| E-01 | [`threat-hunting-dashboard-overview.png`](../evidence/wazuh/threat-hunting-dashboard-overview.png) | Dashboard reachable at `192.168.56.103`. Threat Hunting module, last 24 h, filter `manager.name: wazuh`. Totals: **1,382** alerts, **1** level ≥12, **18** authentication failures, **58** authentication successes. Alert-level evolution and Top 10 MITRE panel. Captured ~10:34 UTC 2026-11-09. | Aggregate across all agents. Not specific to INC-001. MITRE panel shows rule tags, not confirmed attacks. |
| E-02 | [`threat-hunting-dashboard-agents.png`](../evidence/wazuh/threat-hunting-dashboard-agents.png) | Top 5 agents: `windows-host`, `wazuh`, `ubuntu`. Alert volume per agent over time, including the INC-001 period. | Other spikes are not attributed. |
| E-03 | [`inc-001-alerts-5710-5503.png`](../evidence/wazuh/inc-001-alerts-5710-5503.png) | Agent `ubuntu`: rule 5710 at 10:26:49.688, 10:26:55.691, 10:26:59.693 UTC; rule 5503 at 10:26:47.729 UTC. All level 5. | Cropped. See `firedtimes` note in INC-001 §6.1. |
| E-04 | [`inc-001-alert-2502.png`](../evidence/wazuh/inc-001-alert-2502.png) | Agent `ubuntu`: rule 2502, level 10, 10:27:01.695 UTC. | Raw JSON in E-18. |
| E-05 | [`sysmon-alert-92027.png`](../evidence/wazuh/sysmon-alert-92027.png) | Agent `windows-host`: rule 92027, level 4, 2026-11-08 19:39:44.332 UTC. | Corresponds to E-07. |
| E-06 | [`inc-001-alert-5710-raw.json`](../evidence/wazuh/inc-001-alert-5710-raw.json) | Full alert: `location journald`, decoder `sshd`, `srcip 192.168.56.105`, `srcuser invaliduser`, agent `001`, rule 5710, MITRE T1110.001 + T1021.004, `firedtimes 4`. | One of several 5710 alerts. |
| E-07 | [`sysmon-eid1-alert-92027-raw.json`](../evidence/wazuh/sysmon-eid1-alert-92027-raw.json) | Sysmon EID 1 through Wazuh: channel, image, command line (`Get-Date`), SHA256, parent, `integrityLevel High`, agent `002`, decoder `windows_eventchannel`, rule 92027, MITRE T1059.001. | Benign operator test. Contains the Windows computer name and local username. |
| E-10 | [`server-status.txt`](../evidence/wazuh/server-status.txt) | `wazuh-control info` (v4.14.10, revision `rc2`, type server). `agent_control -l` (000/001/002 Active, agents registered `IP: any`). `ss -lntp` (1514 `wazuh-remoted`, 1515 `wazuh-authd`, 443 `node`, 55000 `python3`, 22 `sshd`, 9200/9300 `java` on loopback). | Post-recovery state only. Does not show the TS-01 failure state. |
| E-11 | [`wazuh-server-ossec.conf`](../evidence/wazuh/wazuh-server-ossec.conf) | Manager config: `<remote>` secure/1514/tcp; `<auth>` 1515, `use_password no`; `log_alert_level 3`; `logall no`; indexer `https://127.0.0.1:9200`; active response commented out; cluster disabled; self-monitoring localfiles. | Contains certificate *paths* only, no key material. |
| E-24 | [`ossec-log-excerpt-2026-11-09.txt`](../evidence/wazuh/ossec-log-excerpt-2026-11-09.txt) | Times are UTC. TS-01 failure window: agents' re-enrollment requests rejected as duplicates (10:17:44–10:19:46). Recovery: stop at 10:20:18, `wazuh-analysisd` start at 10:21:01 (pid 4018), `wazuh-remoted` start at 10:21:04 (pid 4100) on 1514/TCP. Later: OBS-01 Sysmon XML rejected (10:47:32), OBS-02 agent key in use ×21 (11:36:43), clean restart at 13:21 (remoted pid 1364), OBS-03 indexer not ready until 13:22:52. | Captured with `tail -150`, so it starts at 10:17:44. One ~20 KB event body is summarised for publication (noted in file). |
| E-25 | [`ossec-log-remoted-history.txt`](../evidence/wazuh/ossec-log-remoted-history.txt) | Every `wazuh-remoted` / `already running` line in `ossec.log` up to 11-09 11:36. `wazuh-remoted` ran as **PID 1245** from 11-08 18:25:58 (origin of the stale PID file). The only logged clean termination is at 11-08 13:31:34. There is **no remoted start between 11-08 18:25:58 and 11-09 10:21:04**, and **no "already running" line anywhere**. Agent key changes at 18:47:35 and 19:14:38. OBS-04 key error from `002` at 19:15:15. | `head -40` cuts off after line 1139 (11-09 11:36:43). Later lines are in E-24. |
| E-28 | [`det-001-alert-2502-srcip-raw.json`](../evidence/wazuh/det-001-alert-2502-srcip-raw.json) | Rule 2502 at 18:07:59.777 UTC on agent `001` after the DET-001 decoder: `decoder.parent: sshd`, **`data.srcip: 192.168.56.105`**, same rule/level/groups/MITRE as E-18. `full_log` PID 2470. | The generating Kali commands and endpoint `auth.log` for this session are not captured. See [DET-001](../detections/DET-001.md). |
| E-31 | [`det-001-followup-tests.txt`](../evidence/wazuh/det-001-followup-tests.txt) | ~18:49 UTC: `cat` of deployed `local_decoder.xml` (stock example + DET-001 **v1**), clean `analysisd -t`; logtest of the INC-001 `Invalid user` line → `sshd` child, `srcip`/`srcport`/`srcuser`, rule 5710 (regression pass); logtest of synthetic `PAM 1 more authentication failure;` under v1 → decoder `sshd` only, rule **5711 level 0** (no alert). | logtest inputs are synthetic (timestamp/PID changed); singular wording not observed on the endpoint. |
| E-33 | [`det-001-alert-2502-real-account-raw.json`](../evidence/wazuh/det-001-alert-2502-real-account-raw.json) | Rule 2502 at 19:02:44.577 UTC, sshd PID 2722, line ends `rhost=192.168.56.105  user=ubuntu`: `data.srcip` **and** `data.dstuser: ubuntu`, i.e. decoded by stock `sshd-pam-host-user`, under DET-001 v2. | — |
| E-34 | [`det-001-dashboard-2502-hits.png`](../evidence/wazuh/det-001-dashboard-2502-hits.png) | Threat Hunting events, `rule.id: 2502 AND agent.name: ubuntu`, 24 h to 19:04 UTC: 4 hits at 10:27:01, 18:07:59, 18:52:34, 19:02:44 UTC (shown in IST). | Columns show no `srcip`. |
| E-35 | [`det-001-v2-restart.txt`](../evidence/wazuh/det-001-v2-restart.txt) | Manager restart 18:59:41 UTC after the v2 change: all daemons running, `wazuh-remoted` (pid 8268) on 1514, `ossec.log` tail with no warnings or errors (one INFO: `netstat not available. Skipping port check`). | v2 file content not printed. |
| E-36 | [`det-001-v2-verification.txt`](../evidence/wazuh/det-001-v2-verification.txt) | 19:13 UTC: `cat` of deployed `local_decoder.xml` (DET-001 **v2**, prematch `… authentication failure`), clean `analysisd -t`. v2 logtest: singular `PAM 1 more authentication failure;` → `srcip` extracted but still rule **5711 level 0** (no alert); plural line → 2502 with `srcip`; real-account `pam_unix` line → `pam`, `dstuser`, `srcip`, 5503. | Synthetic timestamps/PIDs on the summary lines; the plural-line paste ends before the `Alert to be generated` line. |
| E-29 | [`det-001-decoder-development-and-logtest.txt`](../evidence/wazuh/det-001-decoder-development-and-logtest.txt) | DET-001 build session (2026-11-09, ~17:44–18:07 UTC): original `local_decoder.xml` (stock example only); stock `pam` / `sshd-pam-host-user` decoders (the latter needs `user=` after `rhost=`); `wazuh-logtest` baseline for the 2502 and 5503 lines; first draft (child matches, no `srcip`); deployed version (`srcip: 192.168.56.105`, still rule 2502); 5503 regression identical; `wazuh-analysisd -t` clean (18:06:26); restart 18:06:56 with `wazuh-remoted` on 1514. | Ruleset grep and repeated fields trimmed (marked). `nano` edits not captured; final file content **Reported**. |
| E-26 | [`wazuh-control-pstatus-and-journal.txt`](../evidence/wazuh/wazuh-control-pstatus-and-journal.txt) | Installed `pstatus()` (lines 468–493): a daemon counts as running if **any** process has the PID in its PID file. `wazuh-manager` journal: unclean shutdown before the 11-08 18:16 boot; remoted start 18:25:57; at the **11-09 09:57:26 boot, `wazuh-syscheckd already running...` and `wazuh-remoted already running...`**; at 10:20:18–19, `Killing wazuh-remoted...` followed by the stop routine removing stale PIDs 1245 (remoted) and 1230 (syscheckd). | Filtered with `grep`. Final line (10:21:04 `Started wazuh-remoted...`) taken from a later re-run of the same command; the first paste was cut off. |
| E-17 | [`inc-001-alert-5503-raw.json`](../evidence/wazuh/inc-001-alert-5503-raw.json) | Rule 5503 at 10:26:47.729 UTC: decoder `pam`, `full_log` `pam_unix(sshd:auth): authentication failure; … rhost=192.168.56.105` (sshd PID 2296), `srcip` extracted, no `srcuser`, MITRE T1110.001, `firedtimes 1`. | Only one 5503 for three failures. See INC-001 §6.2. |
| E-18 | [`inc-001-alert-2502-raw.json`](../evidence/wazuh/inc-001-alert-2502-raw.json) | Rule 2502 at 10:27:01.695 UTC: decoder `sshd`, `full_log` `PAM 2 more authentication failures; … rhost=192.168.56.105` (PID 2296), **no `data` fields**, MITRE T1110, `firedtimes 1`. | Source IP only in `full_log`. |

### Windows host (`evidence/windows/`)

| ID | File | What it shows | Limits |
|---|---|---|---|
| E-12 | [`windows-agent-ossec.conf`](../evidence/windows/windows-agent-ossec.conf) | Agent points to `192.168.56.103:1514/tcp`, AES, enrollment as `windows-host`/group `default`. Channels: Application, Security (filtered), System, **Sysmon/Operational** (added under a `Sysmon telemetry` comment). FIM, registry, rootcheck, SCA, syscollector at defaults. | File mtime 2026-11-08 19:38 UTC, which is circumstantial. |
| E-13 | [`wazuh-agent-msi-install-excerpt.txt`](../evidence/windows/wazuh-agent-msi-install-excerpt.txt) | Verbatim lines from the msiexec verbose log: install of `wazuh-agent-4.14.10-1.msi` at 2026-11-08 19:13 UTC with `WAZUH_MANAGER=192.168.56.103 WAZUH_AGENT_NAME=windows-host WAZUH_AGENT_GROUP=default`; `SetRegistrationPassword` skipped; `WazuhSvc` installed; status `0`. | Excerpt only. The full 400 KB log is kept outside the repo. Exact msiexec switches not recorded. |
| E-14 | [`sysmon-service-status.txt`](../evidence/windows/sysmon-service-status.txt) | `Sysmon64` service Running. Latest local EID 1: `svchost.exe -k netsvcs -p -s wlidsvc` as SYSTEM, 11:41:32 UTC 2026-11-09. | Version and config are in E-19. |
| E-15 | [`sysmon-local-eid1-export.txt`](../evidence/windows/sysmon-local-eid1-export.txt) | 10 local EID 1 events (~11:45 UTC 2026-11-09): `git.exe`/`conhost.exe` from developer tooling. Shows field completeness and the noise level of the physical host. | Routine activity, not a simulation. Re-encoded UTF-16LE → UTF-8. Contains the Windows computer name, local username and a local project path. |
| E-19 | [`sysmon-config-status.txt`](../evidence/windows/sysmon-config-status.txt) | `Sysmon64.exe -c`: **v15.22**, service `Sysmon64`, driver `SysmonDrv`, config source = install command `Sysmon64.exe -accepteula -i`, SHA256 hashing, network connection **disabled**, image loading **disabled**, CRL checking and DNS lookup enabled, **"No rules installed"**. | Sysinternals URL in the banner normalised from a paste-formatting artefact. |

### Network (`evidence/network/`)

| ID | File | What it shows | Limits |
|---|---|---|---|
| E-16 | [`ip-configuration.txt`](../evidence/network/ip-configuration.txt) | Interfaces for all four machines. Wazuh: `enp0s3` 10.0.2.15 (NAT), `enp0s8` 192.168.56.103/24. Ubuntu: `enp0s3` 10.0.2.15 (NAT), `enp0s8` 192.168.56.104/24. Kali: `eth0` 10.0.2.15 (NAT), `eth1` 192.168.56.105/24. Windows: "Ethernet 2" VirtualBox Host-Only adapter 192.168.56.1/255.255.255.0, no gateway (`Get-NetIPConfiguration` and `ipconfig`). | Windows output trimmed to the host-only adapter for publication (noted in file). |

### VirtualBox (`evidence/virtualbox/`)

| ID | File | What it shows | Limits |
|---|---|---|---|
| E-21 | [`wazuh-vm-details.png`](../evidence/virtualbox/wazuh-vm-details.png) | VirtualBox Manager with three running VMs: `wazuh`, `ubuntu`, `kali`. Details for `wazuh`: 8192 MB RAM, 4 processors, Nested Paging + KVM paravirtualization, `wazuh.vdi` 80 GB (SATA), Adapter 1 NAT, Adapter 2 Host-only ("VirtualBox Host-Only Ethernet Adapter"), no shared folders. | Details shown for `wazuh` only. The "Operating System" field (Ubuntu 24.10) is the VM type label, not the installed OS. |
| E-27 | [`kali-vm-details.png`](../evidence/virtualbox/kali-vm-details.png) | VirtualBox details for `kali`: 3072 MB RAM, 2 processors, `kali-linux-2025.4-virtualbox-amd64.vdi` 80 GB (SATA), Adapter 1 NAT, Adapter 2 Host-only ("VirtualBox Host-Only Ethernet Adapter"). Corrects the 2 GB stated in the original brief. | The VirtualBox type label is "Debian (64-bit)", Kali's base distribution. |

### Kali (`evidence/kali/`)

| ID | File | What it shows | Limits |
|---|---|---|---|
| E-08 | [`inc-001-nmap-and-ssh-attempts.txt`](../evidence/kali/inc-001-nmap-and-ssh-attempts.txt) | Nmap `-sV -sC -p 22` at 10:26 UTC: OpenSSH 9.6p1 Ubuntu 3ubuntu13.20, MAC `08:00:27:91:0C:A9`. SSH as `invaliduser`: three `Permission denied`. | Nmap banner reads `7.991`. Confirm with `nmap --version`. |
| E-30 | [`det-001-validation-ssh.txt`](../evidence/kali/det-001-validation-ssh.txt) | §1: password-only SSH as `invaliduser` to `192.168.56.104`, three `Permission denied` (source of E-28). §2: same as the real account `ubuntu`, three rejected passwords. | No timestamps. §1 tied to E-28 through the endpoint log (E-32); §2 is one of sessions 2685 / 2722, which one is not recorded. |
| E-20 | [`connectivity-checks.txt`](../evidence/kali/connectivity-checks.txt) | `nc -zv 192.168.56.103 443 1514 1515`: all three **open**. `ping -c 3 192.168.56.1`: 3/3 replies, TTL 128, 0% loss. | Post-fix state only. The pre-rule ping failure is not captured. Command has a stray trailing `~`, reproduced as typed. |

### Ubuntu endpoint (`evidence/ubuntu/`)

| ID | File | What it shows | Limits |
|---|---|---|---|
| E-09 | [`inc-001-auth-log-invaliduser.txt`](../evidence/ubuntu/inc-001-auth-log-invaliduser.txt) | INC-001 session: sshd PID 2296, `192.168.56.105:40492`, `Invalid user` at 10:26:43, three `Failed password`, pre-auth close at 10:27:00. Also a local `127.0.0.1` pre-test (2026-11-08). | Grep filter excludes PAM lines and any Nmap-related lines. Superseded by E-23. |
| E-32 | [`det-001-auth-log.txt`](../evidence/ubuntu/det-001-auth-log.txt) | §1: all ten `sshd[2470]` lines of the DET-001 validation session (18:07:41–18:07:58 UTC), context CRON only. §2–3: real-account sessions 2685 (18:52:17–18:52:32) and 2722 (19:02:25–19:02:43) with `user=ubuntu` on PAM lines. | `auth.log` (rsyslog) folds repeats (`message repeated 2 times`); the agent reads journald. |
| E-22 | [`lsb-release.txt`](../evidence/ubuntu/lsb-release.txt) (Ubuntu), [`lsb-release.txt`](../evidence/wazuh/lsb-release.txt) (Wazuh) | Both VMs: `Ubuntu 24.04.5 LTS`, release 24.04, codename noble. | — |
| E-23 | [`auth-log-kali-source-and-inc-001-session.txt`](../evidence/ubuntu/auth-log-kali-source-and-inc-001-session.txt) | All `auth.log` lines from `192.168.56.105` plus all lines of sshd PID 2296: an earlier close (10:06:04), a **successful password login as `ubuntu` (10:24:00–10:24:06)**, nine Nmap probe lines (10:26:23), and the full INC-001 session including `pam_unix` `check pass; user unknown` ×3. | Only lines with the Kali IP or PID 2296. Other sources are not included. |

## Cross-check results

| Item | Sources | Result |
|---|---|---|
| Wazuh server `192.168.56.103` | E-01 URL, E-12 `<address>`, E-13 `WAZUH_MANAGER` | Consistent |
| Ubuntu `192.168.56.104` | E-06 `agent.ip`, E-08 target, E-16 `enp0s8` | Consistent |
| Ubuntu MAC | E-08 `08:00:27:91:0C:A9` ↔ E-16 `fe80::a00:27ff:fe91:ca9` (EUI-64) | Consistent |
| Kali `192.168.56.105` | E-06 `srcip`, E-09, E-16 `eth1` | Consistent |
| Windows `192.168.56.1` | E-07 `agent.ip`, E-16 | Consistent |
| Agent IDs / names | E-06, E-07, E-10, E-12, E-13 | Consistent: `000 wazuh`, `001 ubuntu`, `002 windows-host` |
| Wazuh version 4.14.10 | E-10 (server), E-13 (agent) | Consistent |
| Ports 1514 / 1515 / 443 | E-10 `ss`, E-11, E-12 | Consistent |
| Rule IDs/levels 5710/5, 5503/5, 2502/10, 92027/4 | E-03–E-07, E-17, E-18 | Consistent |
| Three failed passwords in one connection | E-08 (3 prompts), E-09 (3 `Failed password`, PID 2296), E-03 (3 × 5710), E-18 (`PAM 2 more` = 3 total, PID 2296) | Consistent |
| Rule 5503/2502 timestamps | E-17/E-18 `timestamp` ↔ E-03/E-04 dashboard times | Consistent |
| Enrollment without password | E-11 `use_password no`, E-13 `SetRegistrationPassword` skipped | Consistent |
| Sysmon channel collection | E-12 config, E-07 alert | Consistent |
| Sysmon default config / SHA256 only | E-19 (`-i` without config, `HashingAlgorithms: SHA256`) ↔ E-07, E-14, E-15 (`Hashes: SHA256=…` only) | Consistent |
| Manager ports reachable from lab network | E-10 (`0.0.0.0` listeners) ↔ E-20 (`nc` open from Kali) | Consistent |
| Windows timeline | E-13 install 19:13 → E-12 mtime 19:38 → E-07 Sysmon alert 19:39:44 (2026-11-08 UTC) | Consistent sequence |
| TS-01 recovery restart | E-24 `wazuh-remoted` started pid **4100** at 10:21:04 ↔ E-10 `ss` shows pid **4100** on 1514 | Consistent: E-24 lines are from the TS-01 window |
| `firedtimes` counters | E-24 analysisd start 10:21:01 ↔ E-06 5710 `firedtimes 4` ↔ E-23 (four 5710-type lines after 10:21:01) ↔ E-17/E-18 `firedtimes 1` | Consistent |
| Nmap host keys | E-08 (only ECDSA-256 and ED25519 reported) ↔ E-23 (sshd refused `ssh-dss`, `ssh-rsa`, `ecdsa-nistp384`, `ecdsa-nistp521` offers) | Consistent |
| OS versions | E-22 (both 24.04.5) ↔ E-11 header ("ubuntu 24.04") ↔ E-08 OpenSSH `3ubuntu13.20` (noble) | Consistent |

### Inconsistencies and open questions

1. **`firedtimes: 4` vs three visible 5710 alerts.** **Explained.** The analysisd restart at 10:21:01 reset the counter. The fourth match is the `Invalid user` line at 10:26:43 (INC-001 §6.1).
2. **Dashboard shows 1 alert at level ≥12.** No INC-001 alert exceeds level 10. Source unknown.
3. **Nmap version string `7.991`.** The operator confirms the banner printed `7.991`. It is recorded as printed. `nmap --version` would show the full version string.
4. **Wazuh revision `rc2`.** Recorded verbatim from `wazuh-control info`. Not interpreted.
5. **OS version.** **Resolved:** `lsb_release` (E-22) shows 24.04.5 on both VMs. The VirtualBox "Operating System: Ubuntu 24.10" field (E-21) is only the guest-type label chosen at VM creation.
6. **Dashboard scheme.** `node` listens on 443. The `https://` scheme is still not shown in a capture.
7. **Agent IP column.** The operator's agent table lists `001` at `192.168.56.104` and `002` at `192.168.56.1`, while `agent_control -l` (E-10) shows `IP: any` for both. These are different fields, not a conflict. `any` is the *registered* address (the manager has `use_source_ip no`), and `.104` / `.1` are the addresses the agents connect from, as seen in `agent.ip` on alerts (E-06, E-07).
8. **TS-01 recovery steps.** **Resolved:** the journal (E-26) shows the stop routine itself removing the stale `wazuh-remoted` (1245) and `wazuh-syscheckd` (1230) PID files at 10:20:19. No manual cleanup was needed for those.
9. **File placement.** The referenced `E:\Projects\Wazuh\windows-ossec.conf` did not exist. The file was found in the repository root, moved to `evidence/windows/`, and is the copy documented here.
10. **Successful login from the attacker IP before INC-001.** E-23 shows `Accepted password for ubuntu from 192.168.56.105` at 10:24:00 UTC. **Resolved:** the operator confirmed it was their own session (**Reported**). See INC-001 §8, finding 3.
11. **Earlier connection from Kali at 10:06:04** (`Connection closed by 192.168.56.105 port 46138`). **Resolved:** the operator confirmed it was their own activity (**Reported**). The operator also stated that every login and login attempt in the lab is theirs.
12. **"Already running" message not in `ossec.log`.** **Resolved:** it is printed by `wazuh-control` to the systemd journal (E-26, 11-09 09:57:26), together with the same message for `wazuh-syscheckd`.
13. **`wazuh-remoted-1305.pid`.** Still unexplained. No journal or `ossec.log` line mentions PID 1305 for `wazuh-remoted`. It may have been removed by hand. The complete last journal line in E-26 (10:21:04) does not mention it either.

## Evidence still needed

| # | Capture | Proves | Place in |
|---|---|---|---|
| 1 | Dashboard query `agent.id:001`, 10:23:50–10:26:30 UTC | Whether the 10:24 login and the 10:26:23 Nmap probe lines produced alerts | `evidence/wazuh/` |
| 2 | Ubuntu agent `ossec.conf` and `dpkg -s wazuh-agent` | Ubuntu agent version and collection config | `evidence/ubuntu/` |
| 3 | Query for level ≥12 alerts in the dashboard window | Identifies the unexplained alert | `evidence/wazuh/` |
| 4 | VirtualBox details for `ubuntu` (same view as E-21) | Its RAM/CPU (currently **Reported**) | `evidence/virtualbox/` |
| 5 | `Get-NetFirewallRule -DisplayName "Wazuh Lab - Allow ICMPv4 Echo"` (+ `Get-NetFirewallAddressFilter`) | Reported TS-03 rule definition (the ping result is already in E-20) | `evidence/windows/` |
| 6 | Live two-attempt SSH session from Kali (Ctrl+C at the third prompt) + endpoint `auth.log` for its sshd PID | Whether sshd writes the singular `PAM 1 more authentication failure;` line (DET-001 §8) | `evidence/kali/`, `evidence/ubuntu/` |
| 7 | Dashboard query `data.srcip:192.168.56.105` for 18:07–18:08 UTC | 5710, 5503 and 2502 of one session all pivot on `srcip` | `evidence/wazuh/` |

## Redactions

Before publishing, every capture was checked for passwords, enrollment passwords (`authd.pass`), agent keys (`client.keys`), API credentials, tokens and dashboard admin passwords. None of the current evidence contains them.

Content blacked out (`█` in text, black boxes in images):

- **Windows computer name:** in E-07 and E-15, and inside the Sysmon `message` field.
- **Claude desktop app values:** per-session handle values (`--field-trial-handle`, `--pseudonymization-salt-handle`, `--trace-process-track-uuid`) in an E-15 command line.
- **Dashboard screenshots (E-01, E-02, E-34):** an unrelated browser tab title and the dashboard account avatar.

Left in place deliberately:

- The local Windows username (the operator's first name) and local project paths.
- Private lab addresses (`192.168.56.0/24`, VirtualBox NAT `10.0.2.15`), VirtualBox MAC addresses and SSH host-key fingerprints. These are lab-only and are needed to follow the evidence.

Check new captures against the same list before committing them.

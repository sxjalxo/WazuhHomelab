# Deployment

This records how each component was deployed and how to confirm it is working. Status labels are defined in the [README](../README.md#evidence-status-legend).

> **About commands in this document.** Commands under *Executed* appear in captured evidence. Commands under *Recommended verification* are standard checks for re-confirming state. Their output is only claimed where a capture exists. Installation commands that were run but not captured are marked **Pending Verification** instead of reconstructed.

## 1. Wazuh server (all-in-one)

| Item | Value | Status |
|---|---|---|
| Host | VirtualBox VM `wazuh`: 8192 MB RAM, 4 vCPU, 80 GB disk, NAT + Host-only adapters | **Verified** ([VirtualBox details](../evidence/virtualbox/wazuh-vm-details.png)) |
| Guest OS | Ubuntu 24.04.5 LTS (noble) | **Verified** (`lsb_release -a`, [capture](../evidence/wazuh/lsb-release.txt)). The VirtualBox "Operating System" field shows "Ubuntu 24.10 (Oracular Oriole)", but that is only the guest-type label chosen when the VM was created |
| Interfaces | `enp0s3` `10.0.2.15/24` (NAT), `enp0s8` `192.168.56.103/24` (host-only) | **Verified** (`ip -br addr`) |
| Wazuh version | `WAZUH_VERSION="v4.14.10"`, `WAZUH_REVISION="rc2"`, `WAZUH_TYPE="server"` | **Verified** |
| Deployment model | All-in-one: manager, indexer, dashboard, API on one host | **Verified** (`ss`: `wazuh-remoted`, `wazuh-authd`, `java` indexer, `node` dashboard, `python3` API all on one host) |
| Lab IP | `192.168.56.103` | **Verified** |
| Manager name | `wazuh` | **Verified** |
| Alert index pattern | `wazuh-alerts-4.x-YYYY.MM.DD` | **Verified** |
| Installation method / exact commands | — | **Pending Verification** |

The revision string `rc2` is recorded exactly as `wazuh-control info` printed it. It is not interpreted here.

### Manager configuration highlights

From [`evidence/wazuh/wazuh-server-ossec.conf`](../evidence/wazuh/wazuh-server-ossec.conf). All values are **Verified**. The header identifies it as the default Ubuntu 24.04 manager configuration. No lab-specific edits to it have been identified.

| Section | Setting | Value |
|---|---|---|
| `<remote>` | connection / port / protocol / queue | `secure` / `1514` / `tcp` / `131072` |
| `<auth>` | port / `use_password` / `use_source_ip` / `purge` | `1515` / `no` / `no` / `yes` |
| `<alerts>` | `log_alert_level` / `email_alert_level` | `3` / `12` |
| `<global>` | `logall`, `logall_json`, `email_notification` | all `no` |
| `<global>` | `agents_disconnection_time` | `15m` |
| `<indexer>` | host | `https://127.0.0.1:9200` (TLS, certs under `/etc/filebeat/certs/`) |
| `<vulnerability-detection>` | enabled / feed update | `yes` / `60m` |
| `<syscheck>`, `<rootcheck>`, `<sca>`, `syscollector` | enabled | yes (defaults) |
| `<active-response>` | — | **Commented out**: no active response configured |
| `<cluster>` | disabled | `yes` |
| `<ruleset>` | user rules / decoders | `etc/rules`, `etc/decoders` (ready for custom rules; none added yet) |
| Self-monitoring `<localfile>` | sources | `journald`, `/var/ossec/logs/active-responses.log`, `/var/log/dpkg.log`, `df -P`, `netstat -tulpn`, `last -n 20` |

### Executed verification (server)

Full output: [`evidence/wazuh/server-status.txt`](../evidence/wazuh/server-status.txt).

```bash
sudo /var/ossec/bin/wazuh-control info
sudo /var/ossec/bin/agent_control -l
sudo ss -lntp
```

Results:

```text
ID: 000, Name: wazuh (server), IP: 127.0.0.1, Active/Local
ID: 001, Name: ubuntu, IP: any, Active
ID: 002, Name: windows-host, IP: any, Active
```

`ss` shows listeners on 1514 (`wazuh-remoted`), 1515 (`wazuh-authd`), 443 (`node`), 55000 (`python3`), 22 (`sshd`), and on 9200/9300 (`java`, loopback only). See the [ports table](architecture.md#4-ports-and-protocols).

Dashboard access from the Windows host is **Verified**: the Threat Hunting module loads at `192.168.56.103` ([screenshot](../evidence/wazuh/threat-hunting-dashboard-overview.png)). The browser's "Not Secure" indicator is consistent with the self-signed certificate an all-in-one install generates.

### Recommended verification (not yet captured)

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
sudo tail -n 50 /var/ossec/logs/ossec.log
```

## 2. Ubuntu endpoint agent

| Item | Value | Status |
|---|---|---|
| Guest OS | Ubuntu 24.04.5 LTS (noble) | **Verified** (`lsb_release -a`, [capture](../evidence/ubuntu/lsb-release.txt)) |
| Resources | 2 GB / 1 vCPU | **Reported** |
| Interfaces | `enp0s3` `10.0.2.15/24` (NAT), `enp0s8` `192.168.56.104/24` (host-only) | **Verified** |
| Agent name / ID / state | `ubuntu` / `001` / Active, registered with `IP: any` | **Verified** |
| Agent version | — | **Pending Verification** |
| Log source producing SSH alerts | `journald` | **Verified** (`location` in raw alert) |
| Agent `ossec.conf` | — | **Pending Verification** |
| SSH service | `OpenSSH 9.6p1 Ubuntu 3ubuntu13.20`, TCP 22 | **Verified** (Nmap) |
| Enrollment method / commands | — | **Pending Verification** |

Telemetry is **Verified** end to end by INC-001: an sshd failure on the endpoint produced decoded alerts on the manager within about 0.2 s ([INC-001](attack-simulations/INC-001-ssh-authentication-failure.md)).

A local pre-test on 2026-11-08 at 18:51 UTC (an SSH attempt as `invaliduser` from `127.0.0.1`) appears in the endpoint's `auth.log`. Whether it produced Wazuh alerts is **Pending Verification**.

### Recommended verification (not yet captured)

```bash
sudo systemctl status wazuh-agent
sudo cat /var/ossec/etc/ossec.conf
dpkg -s wazuh-agent | grep -i '^version'
```

## 3. Windows endpoint agent

### Installation (Verified)

The agent was installed from `wazuh-agent-4.14.10-1.msi` on **2026-11-08 at 19:13 UTC** (00:43 host time). Evidence: [`evidence/windows/wazuh-agent-msi-install-excerpt.txt`](../evidence/windows/wazuh-agent-msi-install-excerpt.txt).

The MSI was run with these public properties (from the log's `Command Line:` entry):

```text
WAZUH_MANAGER=192.168.56.103 WAZUH_AGENT_NAME=windows-host WAZUH_AGENT_GROUP=default
```

The log is an msiexec verbose log, so verbose logging was enabled. The exact `msiexec` switches were not recorded and are not reconstructed here.

| Install result | Value |
|---|---|
| Product / version | Wazuh Agent 4.14.10 (Wazuh, Inc.) |
| Outcome | `Installation completed successfully`, status `0` |
| Service | `WazuhSvc`, `wazuh-agent.exe`, StartType 2 (automatic) |
| Install path | `C:\Program Files (x86)\ossec-agent\` |
| Registration password | Not used (`SetRegistrationPassword` skipped), consistent with manager `use_password no` |
| Key registered on manager | 2026-11-08 19:14:38 UTC (`wazuh-remoted: Authentication file changed`). The first message at 19:15:15 failed decryption, which was transient ([OBS-04](troubleshooting.md#obs-04-key-error-from-agent-002-right-after-enrollment-2026-11-08-191515-utc)) |

### Configuration (Verified)

From [`evidence/windows/windows-agent-ossec.conf`](../evidence/windows/windows-agent-ossec.conf):

| Item | Value |
|---|---|
| Manager | `192.168.56.103`, port `1514`, `tcp` |
| Encryption | `crypto_method aes` |
| Enrollment | enabled, `agent_name windows-host`, group `default` |
| Keep-alive / reconnect | `notify_time 20`, `time-reconnect 60` |
| Client buffer | enabled, queue `5000`, `500` events/s |
| Event channels | `Application`, `Security` (with query filter), `System`, **`Microsoft-Windows-Sysmon/Operational`** |
| Other modules (defaults) | FIM (`syscheck`) on key system binaries, registry Run keys, Startup folder (realtime); rootcheck; SCA; syscollector; agent-side active response enabled |

The Security channel uses the stock Wazuh query that excludes high-volume event IDs 4656, 4658, 4660, 4663, 4670, 4690, 4703, 4907, 5145, 5152, 5156, 5157 and 5447. This is relevant when planning Windows detections: object-access (4663) and Windows Filtering Platform (5156/5157) events are **not** forwarded.

| Agent state | Value | Status |
|---|---|---|
| Agent name / ID | `windows-host` / `002`, Active, `IP: any` | **Verified** |
| Host-only adapter | `192.168.56.1`, no default gateway | **Verified** |

## 4. Sysmon setup and integration

| Item | Value | Status |
|---|---|---|
| Service | `Sysmon64`, Running | **Verified** (`Get-Service`) |
| Sysmon version | v15.22, driver `SysmonDrv` | **Verified** (`Sysmon64.exe -c`) |
| Install command | `"C:\Program Files\Sysmon\Sysmon64.exe" -accepteula -i` | **Verified**: `-c` records it as the config source |
| Configuration | Built-in default, **no rules installed** | **Verified** |
| Hashing | SHA256 | **Verified** |
| Network connection logging (EID 3) | **Disabled** | **Verified** |
| Image load logging (EID 7) | **Disabled** | **Verified** |
| CRL checking / DNS lookup | Enabled / enabled | **Verified** |
| Event ID 1 generated locally | Yes | **Verified** (`Get-WinEvent`, 11 events captured) |
| Sysmon channel collected by Wazuh agent | Yes | **Verified** (agent `ossec.conf`) |
| Event ID 1 decoded and alerted by Wazuh | Yes, rule `92027` | **Verified** (raw alert) |

### Installation

Run from an elevated PowerShell:

```powershell
cd "C:\Program Files\Sysmon"
.\Sysmon64.exe -accepteula -i
```

`-i` without a configuration file installs Sysmon with its built-in default configuration. This was a deliberate starting point: confirm the pipeline works end to end first, then tune with a community configuration (see [roadmap](roadmap.md) Phase 3).

`Sysmon64.exe -c` ([capture](../evidence/windows/sysmon-config-status.txt)) confirms the result: v15.22, "Config file" set to the install command line itself, `HashingAlgorithms: SHA256`, and **"No rules installed"**. The SHA256 setting matches the `Hashes: SHA256=…` field in every captured EID 1 event.

What this configuration means for detection coverage:

- **Process creation (EID 1) is logged without filtering.** With no rules there are no include/exclude filters, so every process start is recorded. That explains the volume of routine `git.exe`/`conhost.exe` events in the local export.
- **No network-connection events (EID 3)**, because `Network connection: disabled`. Outbound connections by processes (e.g. PowerShell download cradles, C2 beacons) are invisible to Sysmon on this host.
- **No image-load events (EID 7)**, because `Image loading: disabled`. DLL side-loading and suspicious module loads cannot be observed.
- `DNS lookup: enabled` controls reverse-name resolution of addresses in network events. It does not mean DNS queries are being logged.
- Event types other than EID 1 have not been characterised for this configuration. Only EID 1 has been observed in captures.

### Integration

The stock Windows agent configuration collects only Application, Security and System. Sysmon writes to its own channel, so this block was added to the agent's `ossec.conf` (**Verified**: present under a `<!-- Sysmon telemetry -->` comment that is not part of the default file):

```xml
<!-- Sysmon telemetry -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The configuration file's last-modified time is 2026-11-08 19:38 UTC (01:08 host time). The first captured Sysmon alert in Wazuh (rule 92027) follows at 19:39:44 UTC. That sequence is consistent with the block being added, the agent restarted, and a test process launched immediately afterwards. The file timestamp is circumstantial, and the agent restart itself was not captured.

### Executed verification (Sysmon, local)

Captures: [`sysmon-config-status.txt`](../evidence/windows/sysmon-config-status.txt), [`sysmon-service-status.txt`](../evidence/windows/sysmon-service-status.txt), [`sysmon-local-eid1-export.txt`](../evidence/windows/sysmon-local-eid1-export.txt).

```powershell
Sysmon64.exe -c
Get-Service Sysmon64
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1 } -MaxEvents 1 |
  Format-List TimeCreated, Id, Message
```

Both local captures are routine host activity, not simulations: `svchost.exe -k netsvcs -p -s wlidsvc` as SYSTEM, plus `git.exe`/`conhost.exe` launched by developer tooling. They show that Sysmon EID 1 records image, command line, user, integrity level, SHA256 hash and parent process.

### Verified result in Wazuh

The [raw alert](../evidence/wazuh/sysmon-eid1-alert-92027-raw.json) confirms that a Sysmon event survived collection, transport and decoding with its fields intact:

| Field | Value |
|---|---|
| `channel` / `eventID` | `Microsoft-Windows-Sysmon/Operational` / `1` |
| `image` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `commandLine` | `powershell.exe  -NoProfile -Command "Get-Date"` |
| `parentImage` | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| `hashes` | `SHA256=60C9B298…AFE410F` |
| `integrityLevel` | `High` |
| Rule | `92027`, level 4, "Powershell process spawned powershell instance", T1059.001 |

The process was a benign, operator-initiated `Get-Date` run from an elevated PowerShell session. The alert shows that the Sysmon pipeline works. It does not record malicious PowerShell execution.

## 5. Kali Linux attacker

| Item | Value | Status |
|---|---|---|
| Host | VirtualBox VM `kali`: 3072 MB RAM, 2 vCPU, 80 GB disk from the Kali 2025.4 VirtualBox image, NAT + Host-only adapters | **Verified** ([VirtualBox details](../evidence/virtualbox/kali-vm-details.png)) |
| Interfaces | `eth0` `10.0.2.15/24` (NAT), `eth1` `192.168.56.105/24` (host-only) | **Verified** |
| Tools used | `nmap`, OpenSSH client | **Verified** |
| Wazuh agent | None (intentional) | — |
| Clock | UTC−05:00 | **Verified** (Nmap banner) |

### Executed (from captured evidence)

```bash
ip -br addr
nmap -sV -sC -p 22 192.168.56.104
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no invaliduser@192.168.56.104
```

### Connectivity from Kali

| Destination | Port / protocol | Result | Status |
|---|---|---|---|
| Ubuntu endpoint `192.168.56.104` | TCP 22 (SSH) | Open | **Verified** (Nmap, SSH session) |
| Wazuh server `192.168.56.103` | TCP 443 (dashboard) | Open | **Verified** (`nc -zv`) |
| Wazuh server `192.168.56.103` | TCP 1514 (agent events) | Open (after TS-01 recovery) | **Verified** (`nc -zv`) |
| Wazuh server `192.168.56.103` | TCP 1515 (enrollment) | Open | **Verified** (`nc -zv`) |
| Windows host `192.168.56.1` | ICMP echo | 3/3 replies, TTL 128, after firewall rule (TS-03) | **Verified** (`ping -c 3`) |

Capture: [`connectivity-checks.txt`](../evidence/kali/connectivity-checks.txt).

```bash
nc -zv 192.168.56.103 443 1514 1515
ping -c 3 192.168.56.1
```

`nc -z` only completes a TCP handshake and sends no data, so the 1514/1515 checks did not register or impersonate an agent. The `(https)` label in the `nc` output is a service-name lookup by port number, not proof of TLS. The reply TTL of 128 is the Windows default, consistent with the Windows host answering. The attacker being able to reach the manager's enrollment and dashboard ports is relevant to the [security observations](architecture.md#6-security-observations).

## 6. Overall verification checklist

| Check | Result | Status |
|---|---|---|
| Wazuh server version | v4.14.10 | **Verified** |
| Agents `000`, `001`, `002` Active | Yes | **Verified** |
| Manager listening on 1514 / 1515 / 443 / 55000 | Yes | **Verified** |
| Indexer not exposed beyond loopback | Yes | **Verified** |
| Dashboard reachable from Windows host | Yes | **Verified** |
| Alerts present from `ubuntu`, `windows-host`, `wazuh` | Yes | **Verified** |
| Linux auth events decoded with `srcip` / `srcuser` | Yes | **Verified** |
| Sysmon running and producing EID 1 locally | Yes | **Verified** |
| Sysmon channel configured on Windows agent | Yes | **Verified** |
| Sysmon EID 1 decoded in Wazuh with image, command line, hash, parent | Yes | **Verified** |
| Ubuntu agent version and configuration | — | **Pending Verification** |
| Sysmon version and active configuration | v15.22, default, no rules, EID 3/7 disabled | **Verified** |
| Kali → manager TCP 443 / 1514 / 1515 | Open | **Verified** |
| ICMP from Kali to Windows host | 3/3 replies after firewall rule | **Verified** |

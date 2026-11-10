# INC-001: Controlled Invalid-User SSH Authentication Test

| Field | Value |
|---|---|
| Incident ID | INC-001 |
| Date | 2026-11-09 |
| Window (UTC) | 10:26:00 – 10:27:02 |
| Type | Controlled simulation: SSH authentication with a non-existent username |
| Attacker | Kali Linux, `192.168.56.105` |
| Target | Ubuntu endpoint `ubuntu`, Wazuh agent `001`, `192.168.56.104` |
| Outcome | Authentication failed. No session established. Alerts generated. |
| Status | **Verified**: attacker capture, endpoint log and Wazuh alerts all agree |

This was **not** a brute-force or password-spraying attack. It was one SSH connection in which three passwords were typed by hand for a username that does not exist on the target. The goal was to validate the detection pipeline, not to emulate attacker volume.

## 1. Objective

Confirm that an SSH authentication failure on the Linux endpoint is:

1. Logged on the endpoint with the correct source address.
2. Collected by the Wazuh agent and delivered to the manager.
3. Decoded with source IP and username extracted into structured fields.
4. Matched to the appropriate built-in rules and indexed as alerts.
5. Visible and attributable in the Wazuh dashboard.

## 2. Environment

| Role | Host | IP | Details |
|---|---|---|---|
| Attacker | `kali` | `192.168.56.105` | Nmap, OpenSSH client. No Wazuh agent. Clock UTC−05:00. |
| Target | `ubuntu` (agent `001`) | `192.168.56.104` | `OpenSSH 9.6p1 Ubuntu 3ubuntu13.20` on TCP 22. Agent reads sshd events from `journald`. Host-only NIC MAC `08:00:27:91:0c:a9` matches the MAC Nmap reported. |
| Detection | `wazuh` | `192.168.56.103` | Wazuh v4.14.10 all-in-one (**Verified**, `wazuh-control info`) |

## 3. Commands executed

All commands were run on Kali. Full capture: [`evidence/kali/inc-001-nmap-and-ssh-attempts.txt`](../../evidence/kali/inc-001-nmap-and-ssh-attempts.txt).

**Step 1: service reconnaissance (single port).**

```bash
nmap -sV -sC -p 22 192.168.56.104
```

Result: `22/tcp open ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13.20 (Ubuntu Linux; protocol 2.0)`, ECDSA and ED25519 host keys enumerated, VirtualBox MAC `08:00:27:91:0C:A9`. The scan took 3.26 s.

**Step 2: password authentication as a non-existent user.**

```bash
ssh -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    invaliduser@192.168.56.104
```

`PubkeyAuthentication=no` and `PreferredAuthentications=password` force the client straight to password prompts, so every failure is a password failure. Three passwords were entered. The server returned `Permission denied` each time and closed the connection after the third, which matches the observed client output and OpenSSH's default `MaxAuthTries` behaviour. The values typed are not recorded.

## 4. Timeline (UTC)

**Context before the test** (outside INC-001, listed because the source IP is the same):

| Time (UTC) | Source | Event |
|---|---|---|
| 10:06:04.293 | Ubuntu `auth.log` | `sshd[1606]: Connection closed by 192.168.56.105 port 46138`. Operator activity (**Reported**); purpose not recorded |
| 10:21:01 | Wazuh `ossec.log` | `wazuh-analysisd` started (pid 4018) during the [TS-01](../troubleshooting.md) recovery. This resets in-memory rule counters (`firedtimes`) |
| 10:24:00.848 | Ubuntu `auth.log` | `sshd[2091]: Accepted password for ubuntu from 192.168.56.105 port 33832 ssh2`. **Successful login as valid account `ubuntu`**: the operator's own session (**Reported**, see §8, finding 3) |
| 10:24:06.444 | Ubuntu `auth.log` | `Received disconnect from 192.168.56.105 port 33832:11: disconnected by user` / `Disconnected from user ubuntu` |

**INC-001:**

| Time (UTC) | Source | Event |
|---|---|---|
| 10:26 (`05:26 -0500`) | Kali | Nmap `-sV -sC -p 22` scan started, completed in 3.26 s |
| 10:26:23.228 – .430 | Ubuntu `auth.log` | **Nine sshd lines from the scan's probe connections** (PIDs 2281–2294), see §6.4 |
| 10:26:43.235 | Ubuntu `auth.log` | `sshd[2296]: Invalid user invaliduser from 192.168.56.105 port 40492` |
| 10:26:47.640 | Ubuntu `auth.log` | `pam_unix(sshd:auth): check pass; user unknown`, then `pam_unix(sshd:auth): authentication failure; … rhost=192.168.56.105` |
| 10:26:47.729 | Wazuh | Rule **5503** `PAM: User login failed.` (level 5), 89 ms after the source line |
| 10:26:49.595 | Ubuntu `auth.log` | `Failed password for invalid user invaliduser from 192.168.56.105 port 40492 ssh2` (1 of 3) |
| 10:26:49.688 | Wazuh | Rule **5710** (level 5) |
| 10:26:53.187 | Ubuntu `auth.log` | `pam_unix(sshd:auth): check pass; user unknown` |
| 10:26:55.296 | Ubuntu `auth.log` | Failed password (2 of 3) |
| 10:26:55.691 | Wazuh | Rule **5710** (level 5) |
| 10:26:57.818 | Ubuntu `auth.log` | `pam_unix(sshd:auth): check pass; user unknown` |
| 10:26:59.476 | Ubuntu `auth.log` | Failed password (3 of 3) |
| 10:26:59.693 | Wazuh | Rule **5710** (level 5): raw alert captured |
| 10:27:00.810 | Ubuntu `auth.log` | `Connection closed by invalid user invaliduser 192.168.56.105 port 40492 [preauth]` |
| 10:27:00.811 | Ubuntu `auth.log` | `PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.105` |
| 10:27:01.695 | Wazuh | Rule **2502** `syslog: User missed the password more than one time` (level 10), 0.88 s after the source line |

Endpoint lines come from the full session capture ([`auth-log-kali-source-and-inc-001-session.txt`](../../evidence/ubuntu/auth-log-kali-source-and-inc-001-session.txt)). Wazuh times come from the raw alerts' `timestamp` fields or from the dashboard (UTC+05:30) converted to UTC. Each `Failed password` line produced a 5710 alert 0.1–0.4 s later.

Every INC-001 endpoint line shares sshd PID `2296` and source `192.168.56.105`, which ties every alert to the same connection.

## 5. Evidence

| Evidence | What it shows |
|---|---|
| [Kali terminal capture](../../evidence/kali/inc-001-nmap-and-ssh-attempts.txt) | Commands run, Nmap result, three `Permission denied` responses |
| [Ubuntu `auth.log` grep, `invaliduser`](../../evidence/ubuntu/inc-001-auth-log-invaliduser.txt) | First endpoint capture: source `192.168.56.105`, port `40492`, sshd PID `2296`, three failed passwords, pre-auth close |
| [Ubuntu `auth.log` grep, PID 2296 + Kali IP](../../evidence/ubuntu/auth-log-kali-source-and-inc-001-session.txt) | Complete session including PAM lines, the Nmap probe traces, and earlier connections from Kali (including the 10:24 successful login) |
| [Wazuh `ossec.log` excerpt](../../evidence/wazuh/ossec-log-excerpt-2026-11-09.txt) | `wazuh-analysisd` start at 10:21:01, relevant to `firedtimes` |
| [Raw alert, rule 5710](../../evidence/wazuh/inc-001-alert-5710-raw.json) | Decoder output, extracted fields, rule metadata, MITRE mapping |
| [Raw alert, rule 5503](../../evidence/wazuh/inc-001-alert-5503-raw.json) | `pam` decoder, `pam_unix` failure line, `srcip`, MITRE T1110.001 |
| [Raw alert, rule 2502](../../evidence/wazuh/inc-001-alert-2502-raw.json) | `sshd` decoder, PAM summary line, no extracted fields, MITRE T1110 |
| [Screenshot, rules 5710/5503](../../evidence/wazuh/inc-001-alerts-5710-5503.png) | Three 5710 alerts and one 5503 alert on agent `ubuntu` |
| [Screenshot, rule 2502](../../evidence/wazuh/inc-001-alert-2502.png) | Level 10 alert on agent `ubuntu` at 10:27:01.695 UTC |

The `auth.log` capture also contains a separate local test from `127.0.0.1` on 2026-11-08 at 18:51 UTC (sshd PID `6136`). It is not part of INC-001.

## 6. Alert and rule analysis

### 6.1 Rule 5710: `sshd: Attempt to login using a non-existent user` (level 5)

From the [raw alert](../../evidence/wazuh/inc-001-alert-5710-raw.json):

| Field | Value | Meaning |
|---|---|---|
| `location` | `journald` | Collected from the systemd journal, not from `auth.log` |
| `predecoder.program_name` | `sshd` | Syslog-style header parsed |
| `decoder.name` / `parent` | `sshd` / `sshd` | OpenSSH decoder selected |
| `data.srcip` | `192.168.56.105` | Attacker IP extracted as a structured field |
| `data.srcuser` | `invaliduser` | Attempted username extracted |
| `agent.id` / `agent.name` / `agent.ip` | `001` / `ubuntu` / `192.168.56.104` | Reporting endpoint |
| `rule.groups` | `syslog, sshd, authentication_failed, invalid_login` | Useful for grouping and correlation |
| `rule.firedtimes` | `4` | See note below |
| `full_log` | `... sshd[2296]: Failed password for invalid user invaliduser from 192.168.56.105 port 40492 ssh2` | Same PID and port as `auth.log` |

The rule also carries compliance tags (PCI DSS 10.2.4/10.2.5/10.6.1, HIPAA 164.312.b, NIST 800-53 AU.14/AC.7/AU.6, GDPR, TSC, GPG13). These are static rule metadata, not an assessment of compliance.

**Note on `firedtimes: 4`.** The raw alert for the third failed password reports that rule 5710 had fired 4 times. The dashboard excerpt shows three 5710 rows. `firedtimes` is an in-memory counter in `wazuh-analysisd`. `ossec.log` shows analysisd restarting at **10:21:01** during the TS-01 recovery, so the counter started fresh 5½ minutes before the test, and the 2026-11-08 pre-test cannot be included. Between 10:21:01 and 10:26:59, the endpoint log contains exactly four lines from Kali that name an invalid user: `Invalid user invaliduser from …` (10:26:43) and the three `Failed password for invalid user …` lines. That accounts for 4. The `firedtimes: 1` on rules 5503 and 2502 is consistent with the same reset. **Explained.** The 10:26:43 alert row itself falls outside the cropped screenshot, so it is not directly captured.

### 6.2 Rule 5503: `PAM: User login failed.` (level 5)

From the [raw alert](../../evidence/wazuh/inc-001-alert-5503-raw.json):

| Field | Value | Meaning |
|---|---|---|
| `full_log` | `sshd[2296]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.105` | PAM's own failure record for the session (same PID 2296) |
| `predecoder.program_name` | `sshd` | Message emitted inside the sshd process |
| `decoder.name` | `pam` | Selected by message content (`pam_unix(...)`) rather than program name |
| `data.srcip` | `192.168.56.105` | Taken from `rhost=` |
| `data.uid` / `euid` / `tty` | `0` / `0` / `ssh` | sshd's pre-auth context, not a privileged login |
| `data.srcuser` | *absent* | The PAM line names no user. The attempted username exists only in the sshd lines (5710) |
| `rule.groups` | `pam, syslog, authentication_failed` | |
| `rule.firedtimes` | `1` | |
| MITRE | T1110.001 Password Guessing | Rule-associated |

This line was missing from the earlier `auth.log` capture because the grep filtered on `invaliduser`, and the PAM line does not contain the username.

**Why there is only one 5503 for three failed passwords.** The full session log shows that `pam_unix` wrote `check pass; user unknown` for **each** of the three attempts (10:26:47.640, 10:26:53.187, 10:26:57.818). It wrote the `authentication failure; … rhost=…` line only for the **first**. Rule 5503 matched that one line. No alert from the two later `check pass; user unknown` lines appears in the captured evidence.

Each `check pass` line precedes the matching `Failed password` line by 1.66–2.11 s. This is consistent with PAM recording the failure immediately and sshd reporting it after its authentication failure delay.

### 6.3 Rule 2502: `syslog: User missed the password more than one time` (level 10)

From the [raw alert](../../evidence/wazuh/inc-001-alert-2502-raw.json):

| Field | Value | Meaning |
|---|---|---|
| `full_log` | `sshd[2296]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.105` | sshd's end-of-session PAM summary |
| `decoder.name` | `sshd` | |
| `data` | **absent: no `srcip`, no `srcuser`** | The source IP appears only inside `full_log` |
| `rule.groups` | `syslog, access_control, authentication_failed` | |
| `rule.firedtimes` | `1` | |
| MITRE | **T1110** Brute Force (parent technique) | Rule-associated |

"PAM 2 more authentication failures" means one failure already reported plus two more, so three in total. That matches the three `Failed password` lines and the three password prompts on Kali.

Two consequences:

1. **The rule matches one summary line.** sshd writes this line whenever a single connection ends after more than one PAM failure. 2502 is therefore not a frequency/timeframe correlation across events or connections. The same alert would fire for a legitimate user mistyping their password three times. Its level 10 reflects the rule's design, not a judgement that brute force occurred.
2. **The highest-severity alert has no structured source IP.** A query on `data.srcip:192.168.56.105` returns the 5710 and 5503 alerts but **not** 2502. An analyst pivoting on source IP would miss it, and so would any correlation keyed on `srcip`. This is a concrete decoder gap, since addressed by [DET-001](../../detections/DET-001.md): a custom decoder now extracts `srcip` for this line on new alerts. This INC-001 alert is unchanged.

### 6.4 Reconnaissance: logged on the endpoint, no alert observed

The Nmap scan **did** leave traces on the endpoint. Within 0.2 s at 10:26:23 UTC, sshd logged nine lines from `192.168.56.105`, each from a separate short-lived connection (PIDs 2281–2294):

```text
10:26:23.228 sshd[2281]: Connection closed by 192.168.56.105 port 42743
10:26:23.267 sshd[2282]: banner exchange: Connection from 192.168.56.105 port 33160: could not read protocol version
10:26:23.267 sshd[2283]: banner exchange: Connection from 192.168.56.105 port 33172: could not read protocol version
10:26:23.289 sshd[2284]: Unable to negotiate with 192.168.56.105 port 33184: no matching host key type found. Their offer: ssh-dss [preauth]
10:26:23.320 sshd[2286]: Unable to negotiate with 192.168.56.105 port 33188: no matching host key type found. Their offer: ssh-rsa [preauth]
10:26:23.348 sshd[2288]: Connection closed by 192.168.56.105 port 33194 [preauth]
10:26:23.369 sshd[2290]: Unable to negotiate with 192.168.56.105 port 33208: no matching host key type found. Their offer: ecdsa-sha2-nistp384 [preauth]
10:26:23.397 sshd[2292]: Unable to negotiate with 192.168.56.105 port 33220: no matching host key type found. Their offer: ecdsa-sha2-nistp521 [preauth]
10:26:23.430 sshd[2294]: Connection closed by 192.168.56.105 port 33222 [preauth]
```

These lines are attributed to the scan by inference. They fall in the scan's minute, come from Kali's IP, and match what `-sV -sC` does:
- **Version probing:** the `banner exchange … could not read protocol version` lines are probes that never sent an SSH banner.
- **`ssh-hostkey` NSE script:** it opens one connection per host-key algorithm (`ssh-dss`, `ssh-rsa`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, …). sshd refused the four types it does not hold. This agrees with Nmap reporting only ECDSA-256 and ED25519 host keys.

**No Wazuh alert for these lines has been observed.** The alert screenshots are cropped to the authentication phase, so whether any of them matched a rule is **Pending Verification**. Query `agent.id:001` for 10:26:20–10:26:25 UTC to check. If none matched a rule at level 3 or above, they were not retained in Wazuh at all: with `logall`/`logall_json` set to `no` ([manager config](../../evidence/wazuh/wazuh-server-ossec.conf)), non-alerting events are not archived. In that case the recon would exist only in the endpoint's own log.

This is a concrete detection opportunity. Several pre-auth negotiation failures from one source within a second, especially host-key-type enumeration, are a strong scanner signature (see [roadmap](../roadmap.md) Phase 2).

## 7. MITRE ATT&CK mapping

Two kinds of mapping are kept apart below:

- **Rule-associated mapping**: the technique IDs Wazuh attaches to a rule by design. They describe what the rule *can* indicate, and they appear on every alert from that rule regardless of context.
- **Observed behaviour**: what the evidence shows actually happened in this test.

| Technique | Source of mapping | Observed in INC-001? |
|---|---|---|
| **T1110.001** Password Guessing (Credential Access) | Rules 5710 and 5503 | **Partially.** Three password attempts against one non-existent account in a single session. The behaviour class matches, but the scale is a manual test and success was impossible because the account does not exist. Not evidence of a credential-guessing campaign or of compromise. |
| **T1110** Brute Force (Credential Access) | Rule 2502 | **No.** The rule fires on sshd's single end-of-session line summarising three failures (§6.3). Nothing automated or high-volume took place. The tag names the technique the rule is meant to surface, not what happened here. |
| **T1021.004** SSH (Lateral Movement) | Rule 5710 | **No.** No SSH session was established and no movement between hosts occurred. The tag is there because the rule concerns SSH logons. |
| **T1046** Network Service Discovery (Discovery) | Operator's own classification of the Nmap step | **Yes, performed and logged by sshd, but no alert observed.** Nine probe-connection lines exist on the endpoint. No Wazuh alert mapping to T1046 has been seen. See §6.4. |

The dashboard's "Top 10 MITRE ATT&CKs" panel (Valid Accounts, Windows Command Shell, Sudo and Sudo Caching, and others) covers **all** alerts from all agents over 24 hours. Most of those come from routine administration on the endpoints and the Windows host, not from simulations. The panel shows technique tags on alerts, not observed attacks.

## 8. Investigation findings

1. **Source attribution is consistent across three independent sources.** Kali (the commands), the Ubuntu endpoint (`auth.log`: `from 192.168.56.105 port 40492`) and Wazuh (`data.srcip: 192.168.56.105`) all agree.
2. **The targeted account does not exist.** sshd logged `Invalid user` and Wazuh tagged the alerts `invalid_login`. No credential was exposed or at risk.
3. **No successful authentication *within INC-001*, but one successful login from the same source shortly before it.**
   - **Within INC-001:** session 2296 ended pre-auth. The client printed `Permission denied (publickey,password)` and sshd logged `Connection closed by invalid user … [preauth]`.
   - **Before INC-001:** the endpoint log records `Accepted password for ubuntu from 192.168.56.105 port 33832` at **10:24:00 UTC** (sshd PID 2091). It was a 6-second session closed by the client at 10:24:06, 2 min 43 s before the test.
   - **What it is not:** it used the valid local account `ubuntu`, not `invaliduser`, and it came *before* the failed attempts. It is therefore not an outcome of INC-001.
   - **Attribution:** the operator confirmed that this was their own session (**Reported**, operator statement, 2026-11-09). It is therefore classed as authorised administrative access, not attacker activity. The confirmation is the only basis for that classification; nothing in the logs distinguishes it from a malicious login.
   - **Why it is kept in the report:** in a real investigation, a successful password login from the attacking host is the single most important line in this log. Here it was closed out by asking the account owner, which is the right first step, but in production it would also be checked against change records, session activity and the source of the credential.
   - **Did Wazuh alert on it?** Unknown. Suggested query: `agent.id:001 and rule.groups:authentication_success` for 10:23–10:25 UTC.

   An earlier connection from Kali (`Connection closed by 192.168.56.105 port 46138` at 10:06:04, PID 1606) was also the operator's own activity (**Reported**). Its exact purpose was not recorded.
4. **Collection latency was sub-second.** Endpoint log time to alert time was 0.1–0.4 s for each 5710 alert, 89 ms for 5503, and 0.88 s for 2502.
5. **Severity was low to moderate.** Per-attempt alerts were level 5. The session summary escalated to level 10 (2502). The dashboard's single "Level 12 or above" alert in the same 24-hour window is **not** from INC-001, and its source is **Pending Verification**.
6. **Field extraction is uneven across the three rules.** This matters for pivoting and correlation:

   | Rule | Decoder | `data.srcip` | `data.srcuser` |
   |---|---|---|---|
   | 5710 | `sshd` | yes | yes (`invaliduser`) |
   | 5503 | `pam` | yes | no |
   | 2502 | `sshd` | **no** | **no** |

7. **One session, three log sources.** sshd, PAM and the sshd PAM summary each produced a separate alert for the same connection (PID 2296). Grouping alerts by `agent.id` plus time window, or by the PID in `full_log`, rebuilds the session. Grouping by `srcip` alone drops 2502.

### Useful DQL queries

```text
agent.id:001 and data.srcip:192.168.56.105
agent.id:001 and rule.id:(5710 or 5503 or 2502)
agent.id:001 and rule.groups:authentication_failed
data.srcip:192.168.56.105 and rule.groups:authentication_success
agent.id:001 and rule.groups:authentication_success
```

The first query misses 2502 (no `srcip`). The second and third do not depend on extracted fields and return all three rules.

## 9. Limitations

- One manual session with three attempts. Detection of automated, high-volume or distributed guessing has not been tested.
- Only built-in Wazuh rules were evaluated. No custom rules or thresholds were involved.
- Reconnaissance left nine sshd lines on the endpoint, but no alert for them has been observed. There is no network-layer visibility (no IDS/NSM sensor).
- The "attacker" VM was also used for administrative access. The operator logged in as `ubuntu` from Kali at 10:24, minutes before the test. Attacker and admin traffic therefore share a source IP, and only the operator's statement separates them. Future simulations should keep the attack host out of administrative use, or record admin sessions in the incident notes beforehand.
- Rule 2502, the highest-severity alert, carries no structured source IP. Rule 5503 carries no username.
- No active response is configured (the manager's `<active-response>` block is commented out), so the attacker was not blocked.
- IP addresses are DHCP-assigned. Detections or allow-lists tied to these IPs would break if leases change.

## 10. Conclusion

INC-001 shows that the Linux authentication telemetry path works end to end. One SSH connection with three failed passwords for a non-existent user produced sshd and PAM log lines on `ubuntu`. These were collected from journald, delivered to the manager, decoded by the `sshd` and `pam` decoders, and matched to built-in rules 5710 (×3 visible), 5503 and 2502. All were indexed within about two seconds of the source line. The attacker IP was attributed consistently across all evidence sources.

The test also exposed a practical gap: the level-10 alert (2502) has no extracted source IP, so pivoting on `srcip` misses the most severe alert of the session.

The full endpoint log also shows what the alerts did not. The Nmap scan left nine sshd probe lines that produced no observed alert. A successful password login as `ubuntu` came from the same source at 10:24:00, before the test; the operator has confirmed it was their own session.

The test does not show detection of reconnaissance, of real brute-force patterns, or of any compromise resulting from INC-001. The MITRE tags (T1110.001 on 5710/5503, T1110 on 2502, T1021.004 on 5710) are rule metadata. Only T1110.001 loosely matches what happened. Next steps for this scenario are in the [roadmap](../roadmap.md).

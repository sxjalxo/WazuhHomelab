# Roadmap

This separates what exists today from what is planned. Nothing in the *Planned* sections is implemented. Status labels for implemented items are defined in the [README](../README.md#evidence-status-legend).

## Implemented

| Capability | Status |
|---|---|
| Wazuh v4.14.10 all-in-one server on isolated host-only network | **Verified** |
| Ubuntu endpoint agent (`001`) with journald collection | **Verified** |
| Windows host agent (`002`), MSI install, Application/Security/System channels | **Verified** |
| Sysmon v15.22 (`Sysmon64`, default config, no rules) collected via `Microsoft-Windows-Sysmon/Operational` | **Verified** |
| Kali attacker VM on lab network | **Verified** |
| INC-001: invalid-user SSH authentication test, end-to-end trace | **Verified** |
| DET-001: custom decoder extracting `srcip` for rule 2502 ([details](../detections/DET-001.md)) | **Verified**; two-failure sessions still raise no alert (needs a rule) |
| TS-01: manager TCP 1514 listener recovery | Root cause **Verified** (journal + installed `wazuh-control`); recovery **Verified** |

## Phase 1: Close evidence gaps and harden the baseline

Small tasks that make the current state fully verifiable.

- Capture everything listed under *Evidence still needed* in the [evidence index](evidence-index.md).
- **Manager self-health checks (from TS-01).**
  - Add a custom rule on the manager's own `journald` for `wazuh-control` lines containing `already running`, and test whether boot-time lines (written before `wazuh-logcollector` starts) are actually collected.
  - Add a post-boot check that verifies listeners and processes directly (`ss`, `pgrep`), not via `wazuh-control status`, which shares the PID-only check.
  - Adopt ACPI shutdown as the only way the Wazuh VM is stopped.
- Give the **Wazuh server** a static host-only IP first. Agents point at `192.168.56.103` by address, so a lease change disconnects every agent. Endpoint addresses matter less, because agents are registered with `IP: any`.
- **Require an enrollment password** (`<use_password>yes</use_password>` in `<auth>`, plus `authd.pass`), so hosts on the lab network such as Kali cannot register rogue agents. Keep the password out of the repository.
- Confirm that no VirtualBox NAT port-forwarding rules expose the manager's `0.0.0.0` listeners.
- Decide whether to enable `logall_json` for threat-hunting exercises, accepting the extra disk use.
- Identify the one "Level 12 or above" alert shown on the dashboard.
- Take a VirtualBox snapshot of each VM in a known-good state before destructive testing.
- Export the current `ossec.conf` from the server and both agents into the repository, with secrets removed.

## Phase 2: Detection engineering on Linux

- **Close the 2502 field gap. Implemented as [DET-001](../detections/DET-001.md)**; remaining: a live two-attempt test to confirm the singular wording occurs, then a custom rule so two-failure sessions alert (DET-001 §8). Original plan: INC-001 showed that rule 2502 (level 10) extracts no `srcip` from `PAM N more authentication failures; … rhost=<ip>`. Add a custom decoder in `/var/ossec/etc/decoders/local_decoder.xml` that extracts `rhost` as `srcip` for this line. Validate it with `wazuh-logtest` against the captured `full_log`, and confirm that `data.srcip:192.168.56.105` then returns all three INC-001 rules.
- **Custom correlation rule for SSH guessing.** Write a frequency/timeframe rule in `/var/ossec/etc/rules/local_rules.xml` that triggers on N × rule 5710 (or the `authentication_failed` group) from the same `srcip` within T seconds, with a MITRE mapping that reflects the observed behaviour. Test it with `wazuh-logtest` before deploying.
- **INC-002: repeated authentication failures.** Repeat INC-001 at higher volume with a small, documented wordlist against a dedicated test account. Compare built-in rule behaviour with the custom rule.
- **Recon detection from sshd logs.** INC-001's scan left nine sshd lines in 0.2 s (`banner exchange: … could not read protocol version`, `Unable to negotiate … no matching host key type found. Their offer: <type>`, pre-auth closes) with no observed alert. Steps:
  - Run the captured lines through `wazuh-logtest` to see which (if any) built-in rules match.
  - Write a custom child rule plus a frequency rule (e.g. ≥3 pre-auth negotiation failures from one `srcip` within 10 s) mapped to T1046.
  - Re-run the scan to confirm the alert.
- **Network-layer visibility.** Consider adding a network sensor (e.g. Suricata, with its alerts forwarded to Wazuh) for scans that do not touch a logging service.
- **Successful-login-after-failures rule.** Alert when an authentication success from an IP follows recent failures from the same IP.
- Keep tested decoders and rules in `detections/` (files under `detections/rules/`), one `DET-NNN.md` per detection with its test cases (log sample and expected `wazuh-logtest` output).

## Phase 3: Windows telemetry and simulations

- **Sysmon configuration.** The current install has no rules, logs every process creation unfiltered, and has network-connection (EID 3) and image-load (EID 7) logging disabled (`Sysmon64.exe -c`). Replace it with a maintained community baseline (`Sysmon64.exe -c <config.xml>`) that enables EID 3/7 with filtering and reduces EID 1 noise. Document the chosen version, commit the file, and measure the change in event volume reaching Wazuh.
- **Isolated Windows target.** The current Windows endpoint is the operator's physical machine. Before running anything beyond benign commands, add a dedicated **Windows VM** endpoint so simulations do not touch the daily-use host.
- **Large-event decoding test.** On 2026-11-09, `wazuh-analysisd` rejected a Sysmon EID 1 event whose command line held a ~16,000-character `-EncodedCommand` ("Could not read XML string", [OBS-01](troubleshooting.md#obs-01-sysmon-event-rejected-by-the-analysis-engine-104732-utc)). Steps:
  - Reproduce it with a benign, deliberately long encoded command.
  - Find the size at which decoding fails.
  - Document whether such events can be caught another way, e.g. a rule on the analysisd warning or a Sysmon config that excludes known tooling.
- **Atomic simulations.** Run individual, documented techniques (e.g. encoded PowerShell, discovery commands, scheduled task creation) on the Windows VM. Trace each through Sysmon → Wazuh → rule, as done for INC-001.
- **Baseline noise.** Characterise which built-in rules fire routinely on `windows-host` during normal use (e.g. 92027 for legitimate PowerShell use), so real detections can be told apart from noise.
- **Security channel filter.** The agent's default query drops event IDs such as 4663 (object access) and 5156/5157 (WFP connections). Review whether any planned detection needs them, or whether Sysmon covers the same activity. For example, Sysmon EID 3 would cover network connections, but it is currently disabled. With both 5156/5157 filtered and EID 3 off, the Windows host has **no process-level network-connection telemetry** today.

## Phase 4: Alert enrichment and response

- Add GeoIP/asset context where meaningful (limited value on a private subnet, but useful for practice).
- Evaluate threat-intelligence lookups via the Wazuh integrations framework (e.g. hash reputation for Sysmon `hashes`).
- Evaluate Wazuh active response (e.g. `firewall-drop` on the Ubuntu endpoint for repeated SSH failures). Test against Kali and document both the block and the rollback.

## Phase 5: Investigation practice

- Keep the Kali VM for attack traffic only. Do admin SSH to the endpoints from the Windows host, or record any admin session from Kali in the incident notes *before* the test. INC-001 showed that mixing the two forces attribution to rest on the operator's word.
- Write each simulation up as an incident report in the INC-001 format: timeline, evidence, rule analysis, MITRE (rule-mapped vs observed), findings, limitations.
- Build saved searches / dashboards for the queries used in investigations.
- Run at least one multi-stage scenario (recon → credential attempt → successful login → post-auth activity on the endpoint) and document the detection chain and its gaps.

## Explicitly out of scope (for now)

- High availability or multi-node Wazuh clusters.
- Exposing any lab component to the internet.
- Running malware samples on the physical Windows host.

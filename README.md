# AtomicHunt-Inline

## Safe Atomic-Style MITRE ATT&CK Test Runner for Windows Purple Team Exercises

AtomicHunt-Inline is a Windows-based purple-team testing project designed to simulate a broad set of MITRE ATT&CK behaviors in a controlled, safe, and non-destructive way.

The goal of this project is to help security teams validate endpoint visibility, SIEM detection coverage, SOC alerting, Splunk correlation, Windows telemetry, Sysmon rules, and EDR logging without using real malware, credential dumping tools, destructive actions, or invasive attack payloads.

Unlike aggressive offensive testing frameworks, AtomicHunt-Inline focuses on safe atomic-style behavior using native Windows utilities, benign commands, local artifacts, read-only discovery, and cleanup-safe simulations. Each test is executed independently, so one failed or blocked action does not stop the entire run.

This project is intended for authorized purple-team exercises, SOC validation, detection engineering, and internal lab testing.

---

## Project Purpose

AtomicHunt-Inline was created to answer practical detection engineering questions such as:

- Did the SOC see the technique?
- Did the EDR generate telemetry?
- Did Sysmon capture the process chain?
- Did Windows Event Logs record enough useful evidence?
- Which MITRE ATT&CK behaviors are visible?
- Which techniques are missing from detection coverage?
- Which tests were blocked, failed, or silently missed?
- Can Splunk or SIEM correlate the activity into a meaningful story?
- Can analysts distinguish benign atomic simulation from real malicious behavior?

The project is not designed to bypass EDR, steal credentials, deploy malware, or perform destructive activity.

---

## Main Use Cases

AtomicHunt-Inline is useful for:

- Purple-team exercises
- SOC detection validation
- SIEM and Splunk correlation testing
- Windows endpoint telemetry validation
- MITRE ATT&CK coverage mapping
- EDR logging and visibility checks
- Sysmon rule validation
- Security monitoring gap analysis
- Safe lab-based adversary simulation
- Detection engineering training
- Internal security control testing

---

## Core Design Principles

AtomicHunt-Inline follows a safety-first design:

- Use native Windows utilities where possible
- Avoid real malware or weaponized payloads
- Avoid credential theft and credential dumping
- Avoid destructive actions
- Avoid persistence that remains after execution
- Avoid disabling security tools
- Avoid process injection or shellcode
- Generate useful telemetry for defenders
- Keep every test isolated
- Continue execution even if one test fails
- Produce structured reports for analysis
- Make SOC correlation easier through session IDs and consistent fields

---

## What AtomicHunt-Inline Tests

AtomicHunt-Inline covers multiple MITRE ATT&CK tactics, including:

- Reconnaissance
- Resource Development
- Initial Access passive checks
- Execution
- Persistence simulation
- Privilege Escalation discovery
- Defense Evasion stimulus
- Credential Access benign probes
- Discovery
- Lateral Movement enumeration
- Collection
- Command and Control benign network probes
- Exfiltration probes
- Impact read-only checks

---

## Example Simulated Behaviors

The script includes safe simulations and telemetry-generating actions such as:

- PowerShell execution
- CMD execution
- PowerShell EncodedCommand testing
- PowerShell hidden benign child process
- PowerShell Invoke-Expression benign execution
- CMD to PowerShell process chain
- Scheduled task create, run, and delete
- HKCU Run key create and delete simulation
- Service create, query, and delete simulation
- WMIC local process creation
- MSHTA local benign HTA execution
- Regsvr32 silent local probe
- Msiexec quiet local probe
- Rundll32 LOLBin behavior
- Control.exe LOLBin behavior
- Certutil local decoding
- BITS job creation and cancellation
- Hidden file creation and removal
- Masquerading-style benign process execution
- Double-extension artifact creation
- Registry create and delete tests
- DNS queries
- HTTPS connectivity checks
- Custom User-Agent web request
- Cloud reachability probes
- Shadow copy listing without deletion
- Defender status read-only checks
- Firewall profile read-only checks
- Credential location checks without dumping
- Kerberos ticket summary without export
- Browser credential path checks without database extraction
- Local file collection simulation without real exfiltration

---

## Safety Boundaries

AtomicHunt-Inline intentionally avoids high-risk or destructive behavior.

The project does not perform:

- LSASS dumping
- Credential theft
- Mimikatz execution
- Shellcode execution
- Process injection
- AMSI bypass
- Defender tampering
- EDR tampering
- Security product disabling
- Shadow copy deletion
- Ransomware simulation
- Real data exfiltration
- Remote lateral movement using credentials
- Destructive system modification
- Real exploitation
- Real persistence that remains after execution

All tests are designed to be observable, controlled, and suitable for authorized security validation.

---

## VLAN Hopping Simulation Module

This project may also include a VLAN hopping simulation component such as `Invoke-VlanHopSim.ps1`.

The VLAN hopping module is strictly a log-generation and SOC-detection simulation tool. It is not a practical VLAN hopping attack tool and does not behave like real offensive tools such as Yersinia.

The purpose of this module is to generate realistic security artifacts that help SOC analysts, SIEM engineers, and detection teams test whether their monitoring stack can identify VLAN-hopping-style behavior.

The VLAN hopping simulation can generate artifacts for scenarios such as:

- DTP switch spoofing simulation
- 802.1Q double-tagging simulation
- CDP flood simulation
- DTP flood simulation
- Full simulated attack chain correlation
- Reconnaissance to trunk negotiation to VLAN hop to beacon-style event flow

However, this module does not send real packets, does not transmit real DTP frames, does not transmit real CDP frames, does not craft real 802.1Q frames, does not touch network interfaces, does not modify switch configuration, and does not perform actual VLAN hopping.

It only writes simulated attacker artifacts to logging destinations such as:

- Windows Application Event Log
- JSON line log
- CEF log

This makes it useful for:

- SOC correlation testing
- SIEM ingestion testing
- Splunk detection development
- Layer 2 attack visibility exercises
- Analyst training
- Purple-team demonstrations

It should be understood as a defensive simulation and log-generation tool, not an operational network attack tool.

---

## Output Files

Each AtomicHunt-Inline run generates structured output for reporting and detection engineering.

Default output path:

```text
C:\ProgramData\AtomicHuntInline\

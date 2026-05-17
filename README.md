# AtomicHunt-Inline: Safe Atomic-Style MITRE ATT&CK Test Runner

AtomicHunt-Inline is a Windows-based purple-team testing script designed to simulate a broad set of MITRE ATT&CK techniques in a controlled, safe, and non-destructive way.

The goal of this project is to help security teams validate endpoint visibility, SIEM detection coverage, SOC alerting, and EDR telemetry without using real malware, credential dumping tools, destructive actions, or invasive attack payloads.

Unlike aggressive offensive testing frameworks, this runner focuses on safe atomic-style behaviors using native Windows utilities, benign commands, local artifacts, read-only discovery, and cleanup-safe simulations. Each test is executed independently so that one failed or blocked action does not stop the entire run.

## Purpose

This tool is built for:

- Purple-team exercises
- SOC detection validation
- SIEM/Splunk correlation testing
- Windows endpoint telemetry testing
- MITRE ATT&CK coverage mapping
- Safe lab-based adversary simulation
- EDR logging and visibility checks

## What It Tests

AtomicHunt-Inline covers multiple ATT&CK tactics, including:

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

The script includes safe simulations such as:

- PowerShell and CMD execution
- EncodedCommand testing
- Scheduled task creation and cleanup
- HKCU Run key create/delete simulation
- Service create/query/delete simulation
- WMIC local process creation
- MSHTA local benign HTA execution
- Regsvr32 and Msiexec local silent probes
- Rundll32 and Control.exe LOLBin behavior
- Certutil local decoding
- BITS job creation and cancellation
- Hidden file creation/removal
- Masquerading-style benign process execution
- Registry create/delete tests
- DNS and HTTPS connectivity checks
- Shadow copy listing without deletion
- Defender and firewall status read-only checks
- Credential location checks without dumping or extraction

## Safety Design

AtomicHunt-Inline intentionally avoids high-risk or destructive behavior.

The script does not perform:

- LSASS dumping
- Credential theft
- Mimikatz execution
- Shellcode execution
- Process injection
- AMSI bypass
- Defender or EDR tampering
- Shadow copy deletion
- Ransomware simulation
- Real data exfiltration
- Remote lateral movement using credentials
- Destructive system modification

All tests are designed to be observable, controlled, and suitable for authorized security validation.

## Output

Each run generates structured output for reporting and detection engineering:

- JSON result log
- CSV summary table
- TXT table report
- HTML report
- Splunk search file
- Windows Application Event Log entries
- Cleanup script

Default output path:

```text
C:\ProgramData\AtomicHuntInline\

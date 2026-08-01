# SOC Analyst Home Lab

## Overview

This repository documents my SOC analyst home lab built to practice cybersecurity monitoring, log analysis, detection engineering, and incident investigation.

The lab uses a Windows virtual machine with Sysmon installed to generate endpoint telemetry, and Splunk Enterprise to ingest and analyze security logs. The purpose of this project is to build hands-on skills that apply to SOC analyst, security analyst, and information security roles.

## Lab Goals

- Build a virtualized cybersecurity lab environment
- Collect Windows endpoint telemetry using Sysmon
- Ingest and search logs using Splunk
- Create detections for suspicious activity
- Practice analyzing process creation events
- Document findings in an incident-style format
- Build a portfolio of hands-on cybersecurity projects

## Lab Environment

| Component | Details |
|---|---|
| Virtualization | VirtualBox |
| Endpoint VM | Windows 10 |
| Hostname | WIN-SOC-01 |
| Logging Tool | Sysmon |
| SIEM | Splunk Enterprise Free |
| Log Source | Microsoft-Windows-Sysmon/Operational |
| Main Event ID | Sysmon Event ID 1 - Process Creation |
| Test User | soclab |

## Tools Used

- Windows 10
- VirtualBox
- Sysmon
- Splunk Enterprise
- PowerShell
- GitHub
- Git

## Skills Practiced

- Windows event log analysis
- Sysmon configuration
- Splunk SPL searching
- XML field extraction using `rex`
- Process creation analysis
- PowerShell activity detection
- Parent-child process investigation
- Basic detection engineering
- Incident-style documentation

## Completed Labs

| Lab | Description |
|---|---|
| [01 - Sysmon and Splunk Setup](labs/01-sysmon-splunk-setup/) | Installed Sysmon, configured Windows endpoint telemetry, and verified Sysmon logs were ingested into Splunk |
| [02 - Suspicious PowerShell Detection](labs/02-suspicious-powershell-detection/) | Created a Splunk detection for suspicious PowerShell execution using Sysmon Event ID 1 |
| [03 - Failed Login Detection](labs/03-failed-login-detection/) | Planned lab for detecting repeated failed Windows login attempts using Windows Security logs |

## Featured Detection

The first detection created in this lab identifies suspicious PowerShell execution based on command-line arguments such as:

- `ExecutionPolicy Bypass`
- `NoProfile`
- `EncodedCommand`

These flags are not automatically malicious, but they are commonly reviewed by SOC analysts because they can be used in suspicious or unauthorized PowerShell activity.

## Example Detection Query

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" powershell
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| search CommandLine="*ExecutionPolicy Bypass*" OR CommandLine="*EncodedCommand*" OR CommandLine="*-NoProfile*"
| table _time host User Image CommandLine ParentImage

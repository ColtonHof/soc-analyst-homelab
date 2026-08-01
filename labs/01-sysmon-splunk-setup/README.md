# Lab 01: Sysmon and Splunk Setup

## Objective

The objective of this lab was to configure a Windows endpoint to generate detailed security telemetry using Sysmon and ingest those logs into Splunk for analysis.

This lab establishes the foundation for future SOC analyst projects by creating a searchable log pipeline from a Windows VM into Splunk.

## Lab Environment

| Component | Details |
|---|---|
| Virtualization | VirtualBox |
| Endpoint VM | Windows 10 |
| Hostname | WIN-SOC-01 |
| Logging Tool | Sysmon |
| SIEM | Splunk Enterprise Free |
| Log Source | Microsoft-Windows-Sysmon/Operational |
| Splunk Index | main |
| Sourcetype | XmlWinEventLog |

## Tools Used

- Windows 10
- VirtualBox
- Sysmon
- SwiftOnSecurity Sysmon configuration
- Splunk Enterprise
- PowerShell
- Windows Event Viewer

## Setup Summary

In this lab, I installed Sysmon on a Windows 10 virtual machine and configured Splunk to ingest Sysmon Operational logs. I then verified that Sysmon events were successfully searchable in Splunk.

The main log source used was:

```text
WinEventLog:Microsoft-Windows-Sysmon/Operational

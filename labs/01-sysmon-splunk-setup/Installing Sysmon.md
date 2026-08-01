# Installing Sysmon

## Objective

The objective of this section is to install Sysmon on the Windows 10 virtual machine and configure it to collect detailed endpoint telemetry.

Sysmon provides visibility into activity such as process creation, network connections, file creation, and other events that are useful for security monitoring and SOC investigations.

---

## Prerequisites

Before starting, the following should already be completed:

- Windows 10 VM created in VirtualBox
- VM renamed to `WIN-SOC-01`
- Internet access confirmed inside the VM
- PowerShell available with Administrator privileges

---


---

---

## Step 1: Download Sysmon

Sysmon was downloaded from Microsoft Sysinternals.

Search for:

```text
Sysmon Microsoft Sysinternals
```

The correct download page is the Microsoft Learn Sysinternals page for Sysmon.

After downloading, the Sysmon ZIP file was extracted.

---

## Step 2: Create a Tools Folder

A tools directory was created on the Windows VM to store Sysmon and its configuration file.

I created the folder using PowerShell:

```powershell
mkdir C:\Tools
```

The extracted Sysmon files were placed in:

```text
C:\Tools
```

Important files in this folder included:

```text
Sysmon.exe
Sysmon64.exe
Sysmon64a.exe
Eula.txt
```

For this lab, the 64-bit executable was used:

```text
Sysmon64.exe
```

This folder was used to keep the Sysmon executable and configuration file in one organized location before installing Sysmon.

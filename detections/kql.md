# KQL Hunting Queries — MAR-XWORM-2026-01

Microsoft Defender XDR queries for hunting indicators and behaviors associated with the analyzed multi-stage XWorm loader.

---

## Suspicious MSBuild Network Activity

Flags outbound connections from MSBuild.exe to the configured C2 IP or port. MSBuild.exe should not initiate external network connections during normal operation.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "MSBuild.exe"
| where RemotePort == 4445 or RemoteIP == "192.3.171.223"
| project Timestamp, DeviceName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort
```

---

## Run-Key PowerShell Persistence

Detects the HKCU Run value written by the loader to launch a hidden PowerShell script from %TEMP%.

```kql
DeviceRegistryEvents
| where RegistryKey endswith @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueName == "PtwLWb"
| where RegistryValueData has_all ("powershell.exe", "-WindowStyle Hidden", "krtyyj0aomy.ps1")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

---

## Persistent Loader and Script Artifacts

Hunts for the persistence file and PowerShell launcher by filename across all file events.

```kql
DeviceFileEvents
| where FileName in~ ("PtwLWb.exe", "krtyyj0aomy.ps1")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## MSBuild Launched Without Build Arguments

Flags 32-bit MSBuild.exe processes with no build-related arguments — consistent with use as a process hollowing host rather than a legitimate build invocation.

```kql
DeviceProcessEvents
| where FileName =~ "MSBuild.exe"
| where FolderPath has "Framework"          // 32-bit path
| where not (ProcessCommandLine has_any (".proj", ".sln", ".targets", "/t:", "/p:"))
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName
```

---

## Hidden PowerShell Execution from %TEMP%

Broad hunt for hidden PowerShell launcher patterns consistent with the persistence mechanism, not limited to the specific script filename.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_all ("-NoProfile", "-ExecutionPolicy Bypass", "-WindowStyle Hidden")
| where ProcessCommandLine has @"\Temp\"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessParentFileName, AccountName
```

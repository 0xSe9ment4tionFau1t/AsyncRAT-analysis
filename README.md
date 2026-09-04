# AsyncRAT Malware Analysis — Multi-Stage .NET Loader

**Report ID:** MAR-XWORM-2026-01  
**Date:** 31 July 2026  
**TLP:** CLEAR — Disclosure is not limited

Independent analysis of a multi-stage .NET loader that reconstructs assemblies from bitmap resources, establishes user-level persistence, and deploys XWorm RAT inside a hollowed 32-bit MSBuild.exe process.

> Full write-up: [`report/MAR-XWORM-2026-01.pdf`](report/MAR-XWORM-2026-01.pdf)  
> IOCs: [`iocs/iocs.md`](iocs/iocs.md)  
> YARA rules: [`detections/yara.yar`](detections/yara.yar)  
> KQL hunting queries: [`detections/kql.md`](detections/kql.md)

---

## Execution Chain

```
Original hash-named EXE (DJxo / WinForms loader)
 └─► City bitmap RGB extraction
     └─► OptiMax.dll loaded from memory
         └─► Justy("454C6254", "757273", "ProceduralCityGenerator")
             └─► ELbT bitmap + urs custom XOR decryption
                 └─► SystemOptimizerUltimate.dll loaded from memory
                     └─► ExploreLiteralChecker()
                         ├─► 4-second delay + persistence checks
                         │   └─► %APPDATA%\PtwLWb.exe + HKCU Run (PowerShell launcher)
                         └─► FYqEoHsR resource (33,281 bytes)
                             └─► rViDEII decryption → 33,280-byte XWorm PE
                                 └─► Suspended 32-bit MSBuild.exe
                                     └─► Process hollowing
                                         └─► XWormClient-26.exe executing in MSBuild.exe
                                             └─► Raw TCP C2 → 192.3.171.223:4445
```

---

## Analyzed Artifacts

| Artifact | Identifier / Hash | Role |
|---|---|---|
| Original executable | SHA256: `af680b0ac96bd5bbdf2d9f8d67c9ba54e90d139f1c93143ef75e7f8f3b97d1da` | Outer WinForms loader (DJxo) |
| OptiMax.dll | Assembly: OptiMax, v18.9.6.0 | Second-stage bitmap decoder |
| SystemOptimizerUltimate.dll | Assembly: System Optimizer Ultimate, v2025.1.0.0 | Persistence, hollowing, payload extraction |
| XWormClient-26.exe | SHA256: `78c7afbcad01022d73475726e6249c3f6dfefd746af7022207e5ef8a33e4987e` | Final RAT payload |

---

## Key Findings

**Steganography — bitmap-based payload staging**  
Two separate bitmap resources carry executable payloads. The `City` bitmap stores `OptiMax.dll` serialized across RGB pixel channels. The `ELbT` bitmap provides encrypted bytes for `SystemOptimizerUltimate.dll`. Neither resource is a valid image in isolation.

**Delegate obfuscation — 1,201-entry dispatch table**  
`SystemOptimizerUltimate.dll` hides all framework and native API calls behind `ValidateConnectedSet()` wrappers. A static constructor builds a 1,201-entry dictionary mapping static delegate field metadata tokens to their real targets (`Thread.Sleep`, `File.Exists`, `CreateProcess`, `VirtualAllocEx`, etc.), populated at runtime from a compressed embedded resource.

**Reflection by numeric index**  
`OptiMax.dll` selects its next entry point as `GetTypes()[20].GetMethods()[29]` (x86) rather than by name. The outer executable similarly invokes `GetExportedTypes()[0].GetMethods()[0]`. Both patterns are designed to survive renaming and break static analysis.

**Process hollowing into MSBuild.exe**  
The loader creates 32-bit `C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe` with flags `CREATE_SUSPENDED | CREATE_NO_WINDOW`, maps the XWorm PE into the remote process, updates the PEB image-base pointer, modifies the suspended thread context to point at the XWorm entry point, and resumes. This is T1055.012 — the process is not executing a malicious build project.

**User-level persistence without admin**  
The sample operated as a standard user (`WIN10\user`, administrator check returned `false`). Persistence runs through `%APPDATA%\PtwLWb.exe` and an HKCU Run value that launches a hidden PowerShell script from `%TEMP%`.

**XWorm configuration**

| Field | Value |
|---|---|
| C2 host | 192.3.171.223 |
| C2 port | 4445/TCP |
| Protocol | Custom length-prefixed raw TCP |
| Mutex | E46mCFM1aX0TrNpG |
| Config encryption | Rijndael/AES-ECB, key derived from MD5 of mutex |
| Group tag | XWorm V7.1 |

---

## MITRE ATT&CK

| Status | Technique | ID |
|---|---|---|
| Observed | Obfuscated Files or Information: Steganography | T1027.003 |
| Observed | Obfuscated Files or Information: Embedded Payloads | T1027.009 |
| Observed | Deobfuscate/Decode Files or Information | T1140 |
| Observed | Virtualization/Sandbox Evasion: Time Based Evasion | T1497.003 |
| Observed | Registry Run Keys / Startup Folder | T1547.001 |
| Observed | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Observed | Process Injection: Process Hollowing | T1055.012 |
| Observed | System Information Discovery | T1082 |
| Observed | Security Software Discovery | T1518.001 |
| Observed | Non-Application Layer Protocol | T1095 |
| Observed | Encrypted Channel: Symmetric Cryptography | T1573.001 |
| Capability | Screen Capture | T1113 |
| Capability | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Capability | Ingress Tool Transfer | T1105 |
| Capability | System Shutdown/Reboot | T1529 |
| Capability | Network Denial of Service | T1498 |

---

## Detection Opportunities

- Alert on 32-bit `MSBuild.exe` launched without build arguments that initiates external network connections.
- Detect `MSBuild.exe` created suspended, or showing remote memory allocation, `WriteProcessMemory`, thread-context modification, or image unmapping.
- Monitor `HKCU\...\Run` values launching `powershell.exe` with `-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden` and a script in `%TEMP%`.
- Hunt for `%APPDATA%\PtwLWb.exe` and `%TEMP%\krtyyj0aomy.ps1` including deleted-file and registry history artifacts.
- Flag `.NET` applications that load assemblies from byte arrays and immediately select types or methods by numeric index.
- Inspect direct outbound TCP connections from `MSBuild.exe` to non-standard ports, especially port 4445.

See [`detections/kql.md`](detections/kql.md) for Microsoft Defender XDR hunting queries and [`detections/yara.yar`](detections/yara.yar) for YARA rules.

---

## Disclaimer

This analysis was conducted in an isolated test environment on a submitted sample. It is an independent research report and is not an official CISA publication. The report is provided for defensive, educational, and incident-response purposes (TLP:CLEAR). No warranty is provided. The configured C2 infrastructure was not actively contacted during analysis.

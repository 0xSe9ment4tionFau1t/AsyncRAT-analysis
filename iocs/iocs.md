# Indicators of Compromise — MAR-XWORM-2026-01

## Hashes

| Type | Value | Context |
|---|---|---|
| SHA256 | `af680b0ac96bd5bbdf2d9f8d67c9ba54e90d139f1c93143ef75e7f8f3b97d1da` | Original outer loader executable |
| SHA256 | `78c7afbcad01022d73475726e6249c3f6dfefd746af7022207e5ef8a33e4987e` | Recovered XWorm payload (XWormClient-26.exe) |
| MD5 | `b6b94ebf8592f40a76514c647499d7c6` | Recovered XWorm payload |
| SHA1 | `686d14b9af8ec15dc9bdac5b77a46cc1ca984f15` | Recovered XWorm payload |

## Network

| Type | Value | Context |
|---|---|---|
| IPv4 | `192.3.171.223` | Configured XWorm C2 host; operational status not validated |
| Port | `4445/TCP` | Raw TCP C2 port |

## Files

| Path | Context |
|---|---|
| `%APPDATA%\PtwLWb.exe` | Persistent copy of the outer loader |
| `%TEMP%\krtyyj0aomy.ps1` | Obfuscated PowerShell persistence launcher |

## Registry

| Key | Value name | Context |
|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `PtwLWb` | User-level autorun launching hidden PowerShell |

## Processes / Paths

| Value | Context |
|---|---|
| `C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe` | Hollowed x86 host process; legitimate binary abused as container |

## Embedded Resources / Strings

| Value | Context |
|---|---|
| `City` | Bitmap resource in outer EXE containing OptiMax.dll bytes |
| `ELbT` | Bitmap identifier in OptiMax for next-stage encrypted data |
| `FYqEoHsR` | Encrypted XWorm resource in SystemOptimizerUltimate.dll |
| `rViDEII` | Decryption key for FYqEoHsR resource |
| `E46mCFM1aX0TrNpG` | XWorm mutex and AES config key material |
| `XWorm V7.1` | Configured client group tag |
| `PtwLWb` | Persistence filename stem (file + registry value) |
| `krtyyj0aomy.ps1` | PowerShell launcher script filename |

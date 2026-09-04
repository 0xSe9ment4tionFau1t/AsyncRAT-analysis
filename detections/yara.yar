/*
 * YARA rules — MAR-XWORM-2026-01
 * Independent malware analysis — Multi-Stage .NET Loader / XWorm
 *
 * These rules are starting points intended to support detection and hunting.
 * Test against local software inventories before deployment.
 * Behavioral detections should be preferred over signature-only approaches.
 */

rule MultiStage_SystemOptimizer_Loader
{
    meta:
        description  = "Detects strings from the analyzed System Optimizer Ultimate loader stage"
        author       = "Vitalii — Independent Malware Analysis"
        report       = "MAR-XWORM-2026-01"
        date         = "2026-07-31"
        tlp          = "CLEAR"
        reference    = "SystemOptimizerUltimate.dll persistence and resource decryption stage"

    strings:
        $r1 = "FYqEoHsR"      ascii wide   // Encrypted XWorm resource name
        $r2 = "rViDEII"       ascii wide   // Resource decryption key
        $p1 = "PtwLWb"        ascii wide   // Persistence filename stem
        $p2 = "krtyyj0aomy.ps1" ascii wide // PowerShell persistence launcher
        $h1 = "MSBuild.exe"   ascii wide   // Process hollowing target

    condition:
        uint16(0) == 0x5A4D and 4 of them
}

rule XWorm_Client_26_Sample_Family
{
    meta:
        description  = "Detects the analyzed XWorm V7.1 client configuration strings and commands"
        author       = "Vitalii — Independent Malware Analysis"
        report       = "MAR-XWORM-2026-01"
        date         = "2026-07-31"
        tlp          = "CLEAR"
        reference    = "XWormClient-26.exe recovered from FYqEoHsR resource"

    strings:
        $m  = "E46mCFM1aX0TrNpG"          ascii wide   // Mutex + AES config key
        $c1 = "RunShell"                   ascii wide
        $c2 = "StartDDos"                  ascii wide
        $c3 = "StopDDos"                   ascii wide
        $c4 = "sendPlugin"                 ascii wide
        $c5 = "OfflineKeylogger Not Enabled" ascii wide

    condition:
        uint16(0) == 0x5A4D and $m and 2 of ($c*)
}

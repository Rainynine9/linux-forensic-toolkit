# Windows Forensic Toolkit

Personal Windows forensic triage helper for Windows Server 2016, 2019, 2022 and 2025.

## Files

- `windows_forensic_baseline.ps1` — collects host baseline information, selected Windows event logs, persistence locations, network state, a scoped file timeline and SHA256 hashes.

## Requirements

- Windows Server 2016, 2019, 2022 or 2025
- Windows PowerShell 5.1
- Run PowerShell as Administrator
- Access to an approved evidence output location

## Download from GitHub

Replace `YOUR-USERNAME` with your GitHub username or organization:

```powershell
New-Item -ItemType Directory -Path C:\ForensicToolkit -Force
Set-Location C:\ForensicToolkit

Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/YOUR-USERNAME/forensic-toolkit/main/Windows/windows_forensic_baseline.ps1" `
  -OutFile "windows_forensic_baseline.ps1"
```

## SHA256 verification

On the trusted source copy:

```powershell
Get-FileHash .\windows_forensic_baseline.ps1 -Algorithm SHA256
```

On the downloaded copy:

```powershell
Get-FileHash .\windows_forensic_baseline.ps1 -Algorithm SHA256
```

Compare the complete `Hash` values. They must match exactly before execution. Keep the trusted hash independently of the GitHub repository if you need an independent integrity check. A hash downloaded from the same repository does not independently authenticate the publisher.

## Review and run

Review the script before running it. Open an elevated Windows PowerShell 5.1 session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This changes execution policy only for the current PowerShell process. Then run:

```powershell
.\windows_forensic_baseline.ps1 `
  -StartTime "2026-11-01 00:00:00" `
  -EndTime "2026-11-03 23:59:59" `
  -OutputDirectory "E:\Evidence"
```

Use the target server's local time. Confirm its clock and time zone before collection.

## File scan scope

By default, the script checks these locations if present:

- `C:\inetpub\wwwroot`
- `C:\Windows\Temp`
- `C:\ProgramData`
- `C:\Users\Public`
- `C:\Temp`

You can specify additional paths with `-ScanRoots`, for example:

```powershell
.\windows_forensic_baseline.ps1 `
  -StartTime "2026-11-01 00:00:00" `
  -EndTime "2026-11-03 23:59:59" `
  -OutputDirectory "E:\Evidence" `
  -ScanRoots @("C:\inetpub\wwwroot", "D:\Applications", "C:\Windows\Temp")
```

## Output

The script creates three text files in the output directory:

- `*_baseline_*.txt` — system, accounts, processes, services, network, persistence, security and selected event logs
- `*_changed_files_*.txt` — existing files with `LastWriteTime` inside the selected time window
- `*_changed_sha256_*.txt` — SHA256 hashes calculated for files found by the timeline scan

## Important limitations

- This is a triage helper, not a full forensic disk image or complete evidence acquisition.
- File discovery uses `LastWriteTime`; it does not prove when a file was created or who changed it.
- Deleted files are not found by this filesystem scan.
- Event results depend on audit policy, enabled logs, retention and permissions.
- The file scan is limited to configured paths and may take time on large directories.
- Hashes are calculated at collection time, not historical hashes.
- Running commands changes activity on the investigated host. Follow incident-response procedures and collect volatile evidence first where appropriate.
- Prefer an approved external evidence volume rather than the investigated host's system disk.

Use only on systems you are authorized to investigate. Review and test the script before production incident use.

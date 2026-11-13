# Make the PhishGuard scheduled tasks run even when DITO is logged off, using S4U
# ("Service For User": same account, NO stored password). Run ONCE, elevated.
#
# Easiest: right-click this file in Explorer and choose "Run with PowerShell" (approve UAC),
# or from an elevated PowerShell:
#   powershell -NoProfile -ExecutionPolicy Bypass -File D:\PhishGuard\ml\set_tasks_logoff.ps1
#
# It writes what happened to set_tasks_logoff.result.txt next to this file.

$result = Join-Path $PSScriptRoot "set_tasks_logoff.result.txt"
"PhishGuard S4U setup - $(Get-Date -Format s)" | Out-File $result

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    "ERROR: not elevated. Re-run as administrator." | Out-File -Append $result
    Write-Host "Not elevated - re-run as administrator." -ForegroundColor Red
    exit 1
}

try {
    $principal = New-ScheduledTaskPrincipal -UserId "DESKTOP-DTI70EB\DITO" -LogonType S4U -RunLevel Limited
    foreach ($name in @("PhishGuard training", "PhishGuard TI")) {
        Set-ScheduledTask -TaskName $name -Principal $principal | Out-Null
        $t = Get-ScheduledTask -TaskName $name
        $line = "{0,-22} LogonType={1}  User={2}" -f $t.TaskName, $t.Principal.LogonType, $t.Principal.UserId
        $line | Tee-Object -FilePath $result -Append
    }
    "OK: both tasks now run whether logged on or not." | Out-File -Append $result
    Write-Host "Done - both tasks set to S4U (survive log-off and reboot)." -ForegroundColor Green
}
catch {
    "ERROR: $($_.Exception.Message)" | Out-File -Append $result
    Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

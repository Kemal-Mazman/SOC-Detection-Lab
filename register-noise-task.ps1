#Requires -RunAsAdministrator
# register-noise-task.ps1 - schedules benign-provisioning.ps1 to run 5x per weekday.
# Idempotent: -Force overwrites the task if it already exists, so re-running is safe.

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\NoiseGen\benign-provisioning.ps1'
$times     = '08:15','10:40','13:05','15:30','17:20'
$triggers  = $times | ForEach-Object { New-ScheduledTaskTrigger -Daily -At $_ }
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName 'HelpdeskProvisioning' `
    -Action $action -Trigger $triggers -Principal $principal `
    -Description 'Benign account provisioning noise' -Force

Write-Host ""
Write-Host "Registered. Task state:" -ForegroundColor Cyan
Get-ScheduledTask -TaskName 'HelpdeskProvisioning' | Select-Object TaskName, State

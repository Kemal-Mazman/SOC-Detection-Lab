#Requires -RunAsAdministrator
# reset-and-repoint.ps1
# 1. Removes all accounts previously created by the noise generators (clean slate).
# 2. Clears the old provisioning log.
# 3. Re-points the HelpdeskProvisioning scheduled task at the BATCH script,
#    so triggering it generates the full baseline under the SYSTEM account.
#
# After running this, trigger the baseline as SYSTEM with:
#     Start-ScheduledTask -TaskName 'HelpdeskProvisioning'

Write-Host "== Step 1: removing previously provisioned accounts ==" -ForegroundColor Cyan
$ours = @(Get-LocalUser | Where-Object { $_.Description -eq 'Provisioned by helpdesk automation' })
if ($ours.Count -eq 0) {
    Write-Host "  none found." -ForegroundColor DarkGray
} else {
    foreach ($u in $ours) {
        Remove-LocalUser -Name $u.Name
        Write-Host ("  removed {0}" -f $u.Name) -ForegroundColor DarkGray
    }
    Write-Host ("  removed {0} accounts." -f $ours.Count) -ForegroundColor Green
}

Write-Host "== Step 2: clearing old provisioning log ==" -ForegroundColor Cyan
$logPath = 'C:\NoiseGen\provisioning.log'
if (Test-Path $logPath) { Remove-Item $logPath -Force }
Write-Host "  log cleared." -ForegroundColor Green

Write-Host "== Step 3: re-pointing scheduled task at the batch script ==" -ForegroundColor Cyan
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\NoiseGen\batch-provisioning.ps1'
Set-ScheduledTask -TaskName 'HelpdeskProvisioning' -Action $action | Out-Null
Write-Host "  task now runs batch-provisioning.ps1 as SYSTEM." -ForegroundColor Green

Write-Host ""
Write-Host "Done. Now generate the clean baseline as SYSTEM by running:" -ForegroundColor Yellow
Write-Host "    Start-ScheduledTask -TaskName 'HelpdeskProvisioning'" -ForegroundColor Yellow

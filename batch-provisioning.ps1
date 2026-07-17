#Requires -RunAsAdministrator
# batch-provisioning.ps1 - lays down a benign account-provisioning baseline in one run.
# Creates real accounts (real 4720/4722/4724/4732 events, timestamped now), varied names,
# realistic admin minority, paced so nothing looks like a burst attack.
# Prunes down to a small live set at the end (emits 4726) so the box stays clean.
#
# Usage:  powershell -ExecutionPolicy Bypass -File C:\NoiseGen\batch-provisioning.ps1
#         (optional)  ... -File C:\NoiseGen\batch-provisioning.ps1 -Count 80

param(
    [int]$Count   = 60,   # how many provisioning sequences to generate
    [int]$KeepMax = 15    # how many provisioned accounts to leave alive at the end
)

$first = @('james','mary','wei','omar','sofia','liam','priya','noah','fatima','david','elena','sam','hana','tariq','grace','ken','anna','yusuf','lucy','raj')
$last  = @('smith','chen','patel','nguyen','kaur','brown','ali','wilson','garcia','okafor','tanaka','murphy','singh','rossi','kim','walsh','jones','ahmed','park','cole')

function New-Username {
    $f = Get-Random -InputObject $first; $l = Get-Random -InputObject $last
    switch (Get-Random -Maximum 3) {
        0 { "$($f.Substring(0,1))$l" }
        1 { "$f.$l" }
        2 { "$($f.Substring(0,1))$l$(Get-Random -Minimum 1 -Maximum 99)" }
    }
}
function New-RandomPassword {
    $c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%'
    -join ((1..16) | ForEach-Object { $c[(Get-Random -Maximum $c.Length)] })
}

# Realistic weighting: most provisioning is standard Users; a minority get elevated.
# That elevated minority is the benign activity that will trip the attack-chain rule.
$groups  = @('Users','Users','Users','Users','Remote Desktop Users','Remote Desktop Users','Administrators')
$logPath = 'C:\NoiseGen\provisioning.log'
New-Item -ItemType Directory -Path (Split-Path $logPath) -Force | Out-Null

$created = 0; $elevated = 0
Write-Host "Generating $Count benign provisioning sequences..." -ForegroundColor Cyan

for ($i = 1; $i -le $Count; $i++) {
    $username = New-Username
    while (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) { $username = New-Username }
    $password = ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force
    $group    = Get-Random -InputObject $groups
    try {
        New-LocalUser -Name $username -Password $password -FullName $username `
            -Description 'Provisioned by helpdesk automation' -ErrorAction Stop | Out-Null
        Add-LocalGroupMember -Group $group -Member $username -ErrorAction Stop
        Add-Content $logPath ("{0}  CREATED {1}  GROUP {2}" -f (Get-Date -Format s), $username, $group)
        $created++
        if ($group -ne 'Users') { $elevated++ }
    } catch {
        Add-Content $logPath ("{0}  ERROR {1}" -f (Get-Date -Format s), $_.Exception.Message)
    }
    if ($i % 10 -eq 0) { Write-Host "  $i / $Count" -ForegroundColor DarkGray }
    Start-Sleep -Milliseconds (Get-Random -Minimum 400 -Maximum 1500)  # human-ish pacing, not a burst
}

# --- prune down to KeepMax live accounts (emits 4726 deletion events) ---
$ours = @(Get-LocalUser | Where-Object { $_.Description -eq 'Provisioned by helpdesk automation' })
if ($ours.Count -gt $KeepMax) {
    $toDelete = $ours | Get-Random -Count ($ours.Count - $KeepMax)
    foreach ($u in $toDelete) {
        Remove-LocalUser -Name $u.Name
        Add-Content $logPath ("{0}  DELETED {1}" -f (Get-Date -Format s), $u.Name)
    }
}

Write-Host ""
Write-Host "Done. Created $created accounts ($elevated elevated), pruned to $KeepMax live." -ForegroundColor Green
Write-Host "Check Splunk for a burst of fresh 4720 with randomised created_account." -ForegroundColor Green

#Requires -RunAsAdministrator
# benign-provisioning.ps1 - benign twin of the local-account-admin-RDP chain.
# Simulates a helpdesk admin provisioning real users.
# Emits: 4720 (created), 4722 (enabled), 4724 (pw set), 4732 (group add),
#        and occasional 4726 (deleted). Names randomised every run by design.

$first = @('james','mary','wei','omar','sofia','liam','priya','noah','fatima','david','elena','sam','hana','tariq','grace','ken')
$last  = @('smith','chen','patel','nguyen','kaur','brown','ali','wilson','garcia','okafor','tanaka','murphy','singh','rossi','kim','walsh')

function New-Username {
    $f = Get-Random -InputObject $first; $l = Get-Random -InputObject $last
    switch (Get-Random -Maximum 3) {
        0 { "$($f.Substring(0,1))$l" }                                    # jsmith
        1 { "$f.$l" }                                                     # james.smith
        2 { "$($f.Substring(0,1))$l$(Get-Random -Minimum 1 -Maximum 99)" } # jsmith42
    }
}
function New-RandomPassword {
    $c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%'
    -join ((1..16) | ForEach-Object { $c[(Get-Random -Maximum $c.Length)] })
}

# Realistic weighting: most provisioning is standard users; a minority get admin -
# that admin minority is the false positive that trips your chain rule.
$groups  = @('Users','Users','Users','Remote Desktop Users','Remote Desktop Users','Administrators')
$logPath = 'C:\NoiseGen\provisioning.log'
New-Item -ItemType Directory -Path (Split-Path $logPath) -Force | Out-Null

# --- provision one account ---
$username = New-Username
while (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) { $username = New-Username }
$password = ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force
$group    = Get-Random -InputObject $groups
try {
    New-LocalUser -Name $username -Password $password -FullName $username `
        -Description 'Provisioned by helpdesk automation' -ErrorAction Stop | Out-Null
    Add-LocalGroupMember -Group $group -Member $username -ErrorAction Stop
    Add-Content $logPath ("{0}  CREATED {1}  GROUP {2}" -f (Get-Date -Format s), $username, $group)
} catch {
    Add-Content $logPath ("{0}  ERROR {1}" -f (Get-Date -Format s), $_.Exception.Message)
}

# --- occasional deprovision (keeps account count bounded, adds 4726 lifecycle noise) ---
if ((Get-Random -Maximum 100) -lt 40) {
    $ours = @(Get-LocalUser | Where-Object { $_.Description -eq 'Provisioned by helpdesk automation' })
    if ($ours.Count -gt 6) {
        $victim = Get-Random -InputObject $ours
        Remove-LocalUser -Name $victim.Name
        Add-Content $logPath ("{0}  DELETED {1}" -f (Get-Date -Format s), $victim.Name)
    }
}

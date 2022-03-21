# BE CAREFUL !! Not fully tested.

Write-Host "    [+] Remove exclusions"

# Add the whole system in Defender exclusions

67..90|foreach-object{
    $drive = [char]$_
    Remove-MpPreference -ExclusionPath "$($drive):\" -ErrorAction SilentlyContinue
    Remove-MpPreference -ExclusionProcess "$($drive):\*" -ErrorAction SilentlyContinue
}


Write-Host "    [+] Enable scanning engines (Set-MpPreference)"

Set-MpPreference -DisableArchiveScanning 0 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring 0 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIntrusionPreventionSystem 0 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection 0 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRemovableDriveScanning 0 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen 0 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 0 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningNetworkFiles 0 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning 0 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring 0 -ErrorAction SilentlyContinue

Write-Host "    [+] Set default actions to default (Set-MpPreference)"

Set-MpPreference -LowThreatDefaultAction 6 -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction 2 -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction 2 -ErrorAction SilentlyContinue

Write-Host "    [+] Enable services"

$need_reboot = $false

# WdNisSvc Network Inspection Service 
# WinDefend Antivirus Service
# Sense : Advanced Protection Service

$svc_list = @("WdNisSvc", "WinDefend", "Sense")
foreach($svc in $svc_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 2) {
            Write-Host "        [i] Service $svc already enabled"
        } else {
            Write-Host "        [i] Enable service $svc (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 2
            $need_reboot = $true
        }
    } else {
        Write-Host "        [i] Service $svc does not exists !"
    }
}

Write-Host "    [+] Enable drivers"

# WdnisDrv : Network Inspection System Driver
# wdfilter : Mini-Filter Driver
# wdboot : Boot Driver

$drv_list = @("WdnisDrv", "wdfilter", "wdboot")
foreach($drv in $drv_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 2) {
            Write-Host "        [i] Driver $drv already enabled"
        } else {
            Write-Host "        [i] Enable driver $drv (next reboot)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 2
            $need_reboot = $true
        }
    } else {
        Write-Host "        [i] Driver $drv does not exists !"
    }
}

# Check if service running or not
if($(GET-Service -Name WinDefend).Status -eq "Running") {   
    Write-Host "    [+] WinDefend Service is running"
} else {
    Write-Host "    [+] WinDefend Service not running (reboot required)"
    $need_reboot = $true
}

if($need_reboot) {
    Write-Host "    [+] Please reboot and **start again**."

} else {

    # Configure the Defender registry to disable it (and the TamperProtection)
    # editing HKLM:\SOFTWARE\Microsoft\Windows Defender\ requires to be SYSTEM
    # So let's use a scheduled task as System as attackers do ;-)
    
    Write-Host "    [+] Enable all functionnalities with registry keys (SYSTEM privilege)"

    $commands = @(
    # Cloud-delivered protection:
    'Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SpyNetReporting',
    # Automatic Sample submission
    'Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SubmitSamplesConsent',
    # Tamper protection
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -Value 0',
    # Enable in registry
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 0',
    'Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 0'
    )

    foreach ($command in $commands) {
        # To bypass escaping characters (doubles quotes), I'm using base64 encoded commands.
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
        $encodedcommand = [Convert]::ToBase64String($Bytes)
        $Time = New-ScheduledTaskTrigger -At 00:00 -Once
        $Action = New-ScheduledTaskAction -Execute PowerShell.exe -Argument "-NoProfile -encodedcommand $encodedcommand"
        $Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName "Elevated-Command" -Trigger $Time -Action $Action -RunLevel Highest -User "nt authority\system" -Settings $Settings
        Start-ScheduledTask -TaskPath "\" -TaskName "Elevated-Command"
        Start-Sleep 2
        Unregister-ScheduledTask -TaskName "Elevated-Command" -Confirm:$false
    }

}
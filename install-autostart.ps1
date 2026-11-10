# Registers a Windows scheduled task that starts the monitor hidden at every login,
# keeps it running on battery, never times it out, and restarts it if it crashes.
# Run once:      .\install-autostart.ps1
# Remove later:  Unregister-ScheduledTask -TaskName "Internet Monitor" -Confirm:$false

$pyw = (Get-Command pythonw.exe -ErrorAction Stop).Source
$me = "$env:USERDOMAIN\$env:USERNAME"

$action    = New-ScheduledTaskAction -Execute $pyw -Argument "`"$PSScriptRoot\monitor.py`" --quiet" -WorkingDirectory $PSScriptRoot
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $me
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
               -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
               -MultipleInstances IgnoreNew -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName "Internet Monitor" -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Description "Records internet drops and lag spikes ($PSScriptRoot)" -Force | Out-Null
Write-Host "Auto-start installed: the monitor will start hidden at every login (using $pyw)."
Write-Host "If a monitor is already running, the new one exits on its own, so it's safe to start it now too:"
Write-Host "  Start-ScheduledTask -TaskName 'Internet Monitor'"

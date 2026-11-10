# Start the monitor hidden in the background (no console window).
# To start it automatically at every login, run .\install-autostart.ps1 once.
# Only one monitor can run at a time; extra launches exit immediately.
# Stop it with:  Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" | Where-Object CommandLine -like '*monitor.py*' | ForEach-Object { Stop-Process -Id $_.ProcessId }

$pythonw = (Get-Command pythonw.exe -ErrorAction Stop).Source
Start-Process -FilePath $pythonw -ArgumentList "`"$PSScriptRoot\monitor.py`" --quiet" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
Write-Host "Internet monitor running in the background. Data: $PSScriptRoot\data\monitor.db"

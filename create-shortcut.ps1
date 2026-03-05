# Creates a Desktop shortcut to chat.bat
# Run in PowerShell:  powershell -ExecutionPolicy Bypass -File .\create-shortcut.ps1

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $here 'chat.bat'
if (-not (Test-Path $target)) {
  throw "chat.bat not found at: $target"
}

$desktop = [Environment]::GetFolderPath('Desktop')
$linkPath = Join-Path $desktop 'Terminal Chat.lnk'

$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut($linkPath)
$lnk.TargetPath = $target
$lnk.WorkingDirectory = $here
$lnk.WindowStyle = 1
$lnk.Description = 'Terminal Chat (CMD)'
$lnk.IconLocation = "$env:SystemRoot\System32\cmd.exe,0"
$lnk.Save()

Write-Host "Created shortcut: $linkPath"

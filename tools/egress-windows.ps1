<#
Per-process network egress of Handover on Windows, from Windows Filtering Platform audit events
(5156 = connection allowed, 5157 = blocked). Needs an elevated PowerShell. Works on any Windows language
(the audit sub-category is addressed by GUID; the previous audit policy is saved with `auditpol /backup`).

  .\tools\egress-windows.ps1 -Start                                  enable auditing, clear the DNS cache, note the time
  ... run the scenario (install, open the app, connect, transfer files ...) ...
  .\tools\egress-windows.ps1 -Report -Allow <server-ip>[,<ip>...]    list what handover.exe talked to; exit 1 on any leak
  .\tools\egress-windows.ps1 -Report -Allow <server-ip> -Restore     same, then put the audit policy back

The report fails if handover.exe connected to a non-loopback address outside -Allow, if any connection was blocked,
or if the DNS client cache holds a name matching a known vendor/third-party pattern. The DNS cache cannot be
attributed to a process, so other names in it are only listed.
#>
param(
  [switch]$Start,
  [switch]$Report,
  [switch]$Restore,
  [string[]]$Allow = @(),
  [string]$Process = 'handover.exe'
)
$ErrorActionPreference = 'Stop'
$guid = '{0CCE9226-69AE-11D9-BED3-505054503030}'   # Filtering Platform Connection
$state = Join-Path $env:ProgramData 'handover-egress-state.json'
$backup = Join-Path $env:ProgramData 'handover-egress-audit.csv'
$vendor = 'rustdesk|stun\.|nip\.io|telegram'

function Assert-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run this in an elevated PowerShell' }
}

function Restore-Audit {
  if (Test-Path $backup) { auditpol /restore /file:$backup | Out-Null; Remove-Item $backup -Force; Write-Host 'audit policy restored' }
}

Assert-Admin
if ($Start) {
  if (-not (Test-Path $backup)) { auditpol /backup /file:$backup | Out-Null }
  auditpol /set /subcategory:$guid /success:enable /failure:enable | Out-Null
  Clear-DnsClientCache
  @{ start = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content $state
  Write-Host "auditing on, recording since $((Get-Content $state | ConvertFrom-Json).start)"
  exit 0
}
if (-not $Report) { throw 'use -Start or -Report' }
if (-not (Test-Path $state)) { throw 'no recording in progress: run -Start first' }
$since = [datetime]((Get-Content $state | ConvertFrom-Json).start)

$rows = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5156, 5157; StartTime = $since } -ErrorAction SilentlyContinue | ForEach-Object {
  $x = [xml]$_.ToXml(); $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
  if ($d['Application'] -match [regex]::Escape($Process)) {
    [pscustomobject]@{ Id = $_.Id; Proto = $d['Protocol']; Dst = $d['DestAddress']; Port = $d['DestPort'] }
  }
}
$rows = @($rows)
$leaks = @()
foreach ($g in ($rows | Group-Object Id, Proto, Dst, Port | Sort-Object Name)) {
  $r = $g.Group[0]
  $loop = $r.Dst -match '^(127\.|::1$|0\.0\.0\.0$|::$)'
  $ok = $loop -or ($Allow -contains $r.Dst)
  $verdict = if ($r.Id -eq 5157) { 'BLOCKED' } elseif ($ok) { 'ALLOWED' } else { 'LEAK' }
  if ($verdict -ne 'ALLOWED') { $leaks += $g }
  '{0,-8} {1,4}x  proto {2,-3} {3}:{4}' -f $verdict, $g.Count, $r.Proto, $r.Dst, $r.Port
}
Write-Host "$Process events since ${since}: $($rows.Count)"
$names = @(Get-DnsClientCache | ForEach-Object { $_.Entry } | Sort-Object -Unique)
$bad = @($names | Where-Object { $_ -match $vendor })
foreach ($n in $names) { '{0,-8} dns {1}' -f $(if ($bad -contains $n) { 'LEAK' } else { 'info' }), $n }
if ($Restore) { Restore-Audit; Remove-Item $state -Force -ErrorAction SilentlyContinue }
if ($rows.Count -eq 0) { Write-Host 'RESULT: INCONCLUSIVE (no events from the process: was the scenario run?)'; exit 2 }
if ($leaks.Count -gt 0 -or $bad.Count -gt 0) { Write-Host 'RESULT: FAIL (unexpected egress)'; exit 1 }
Write-Host 'RESULT: PASS (no unexpected egress)'
exit 0

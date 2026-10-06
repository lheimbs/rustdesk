<#
Sign files with a code-signing certificate that already exists in the CurrentUser\My store of the build host.

  .\tools\sign-windows.ps1 -Files a.exe,b.dll [-Thumbprint <sha1>] [-Subject 'CN=...']

The certificate is found by -Thumbprint, or by -Subject (default 'CN=Handover'). Nothing is created unless you pass
-Create, which makes a NEW self-signed code-signing certificate (10 years, private key exportable) and writes its
PUBLIC part to handover-signing.cer for tools/trust-windows-cert.ps1. Create your real certificate yourself (so the
private key stays under your control) and only point this script at it. No timestamp server is contacted.

Note: a self-signed certificate that you trust on a machine fixes "unknown publisher" prompts and Defender/SmartScreen
reputation for that machine. It does NOT satisfy Windows 11 Smart App Control in enforcement mode, which only accepts
certificates that chain to Microsoft's trusted root program.
#>
param(
  [Parameter(Mandatory = $true)][string[]]$Files,
  [string]$Thumbprint,
  [string]$Subject = 'CN=Handover',
  [switch]$Create
)
$ErrorActionPreference = 'Stop'
$now = Get-Date
$certs = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.NotAfter -gt $now -and $_.HasPrivateKey }
$cert = if ($Thumbprint) { $certs | Where-Object { $_.Thumbprint -eq $Thumbprint.ToUpper() } | Select-Object -First 1 }
        else { $certs | Where-Object { $_.Subject -eq $Subject } | Select-Object -First 1 }
if (-not $cert) {
  if (-not $Create) { throw "no valid code-signing certificate with a private key found (Thumbprint '$Thumbprint', Subject '$Subject'); create one yourself, or pass -Create to make a new self-signed one" }
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable -NotAfter $now.AddYears(10) -HashAlgorithm SHA256
  Export-Certificate -Cert $cert -FilePath handover-signing.cer | Out-Null
  Write-Host "created certificate $($cert.Thumbprint); public certificate: handover-signing.cer"
}
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'signtool.exe not found (install the Windows SDK)' }
foreach ($f in $Files) {
  & $signtool.FullName sign /fd SHA256 /sha1 $cert.Thumbprint $f | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "signing failed: $f" }
}
Write-Host "signed $($Files.Count) file(s) with certificate $($cert.Thumbprint)"

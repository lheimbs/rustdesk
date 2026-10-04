<#
Sign the Handover binaries with a personal self-signed code-signing certificate.

  .\tools\sign-windows.ps1 -Files handover-install.exe,flutter\build\windows\x64\runner\Release\handover.exe

First run creates the certificate (CurrentUser\My, 10 years, exportable) and writes handover-signing.cer,
the PUBLIC certificate to import on each target machine (tools/trust-windows-cert.ps1). Keep the private
key (handover-signing.pfx, if you export it) off the build host. No timestamp server is contacted.
Note: a self-signed certificate does not satisfy Windows 11 Smart App Control in enforcement mode.
#>
param(
  [Parameter(Mandatory = $true)][string[]]$Files,
  [string]$Subject = 'CN=Handover (me.heimbs)'
)
$ErrorActionPreference = 'Stop'
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date) } | Select-Object -First 1
if (-not $cert) {
  $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(10) -HashAlgorithm SHA256
  Export-Certificate -Cert $cert -FilePath handover-signing.cer | Out-Null
  Write-Host "created certificate $($cert.Thumbprint); public certificate: handover-signing.cer"
}
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw 'signtool.exe not found (install the Windows SDK)' }
foreach ($f in $Files) {
  & $signtool.FullName sign /fd SHA256 /sha1 $cert.Thumbprint $f
  if ($LASTEXITCODE -ne 0) { throw "signing failed: $f" }
}
Write-Host "signed: $($Files -join ', ')  (certificate thumbprint $($cert.Thumbprint))"

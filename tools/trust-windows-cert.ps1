<#
Trust the Handover signing certificate on THIS machine (run elevated). Needed once per target machine.

  .\trust-windows-cert.ps1 -Cer handover-signing.cer

Adds the public certificate to LocalMachine\Root and LocalMachine\TrustedPublisher so that Windows shows the
publisher in UAC and accepts the signature. Verify the thumbprint against the one printed by sign-windows.ps1.
#>
param([Parameter(Mandatory = $true)][string]$Cer)
$ErrorActionPreference = 'Stop'
$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (Resolve-Path $Cer)
Write-Host "importing certificate $($c.Subject) thumbprint $($c.Thumbprint)"
foreach ($store in 'Root', 'TrustedPublisher') {
  Import-Certificate -FilePath $Cer -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null
}
Write-Host 'done'

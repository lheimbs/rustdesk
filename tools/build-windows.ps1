<#
Build the Handover Windows installer (handover-install.exe) on a Windows 10/11 x64 build host.

  .\tools\build-windows.ps1                       # reads HANDOVER_* from .env (see .env.example)
  .\tools\build-windows.ps1 -Server <host> -Key <id_ed25519.pub of your hbbs>   # or pass them explicitly

Prerequisites (see docs/TRUST_HARDENING_PLAN.md, Phase W): Visual Studio 2022 Build Tools (C++ x64 + Windows SDK),
LLVM 15.0.6, Rust 1.75 (rust-toolchain.toml), Flutter 3.24.5, Python 3 (+ pip install brotli),
vcpkg at 9e593bb18ea69cc5095e012465dcd675a822ed0d with `vcpkg install --triplet x64-windows-static`
run in the repo root (installed under -VcpkgInstalled), and the generated bridge files
(tools/gen-bridge.sh on Linux, copied over: src/bridge_generated*.rs, flutter/lib/generated_bridge*.dart).
The server address and key are compiled into the binary; a release build refuses to build without them.
#>
param(
  [string]$Server,
  [string]$Key,
  [string]$VcpkgRoot = 'C:\dev\vcpkg',
  [string]$VcpkgInstalled = 'C:\dev\vcpkg_installed',
  [string]$FlutterBin = 'C:\dev\flutter\bin',
  [switch]$Sign,                # sign the app files and the installer (see tools/sign-windows.ps1)
  [string]$SignThumbprint,
  [string]$SignSubject = 'CN=Handover',
  [switch]$SignCreate           # create a NEW self-signed certificate when none exists (test use)
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$dotenv = @{}
if (Test-Path .env) {
  Get-Content .env | ForEach-Object {
    if ($_ -match '^\s*([A-Z_][A-Z0-9_]*)=(.*)$') { $dotenv[$Matches[1]] = $Matches[2].Trim().Trim('"', "'") }
  }
}
if (-not $Server) { $Server = $dotenv['HANDOVER_RENDEZVOUS_SERVER'] }
if (-not $Key) { $Key = $dotenv['HANDOVER_SERVER_KEY'] }
if (-not $Server -or -not $Key) { throw 'set HANDOVER_RENDEZVOUS_SERVER and HANDOVER_SERVER_KEY in .env (see .env.example) or pass -Server and -Key' }

$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found: $vcvars" }
$env:HANDOVER_RENDEZVOUS_SERVER = $Server
$env:HANDOVER_SERVER_KEY = $Key
$env:VCPKG_ROOT = $VcpkgRoot
$env:VCPKG_INSTALLED_ROOT = $VcpkgInstalled
$env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin'
$env:VCPKG_DISABLE_METRICS = '1'
$env:PATH = "$env:USERPROFILE\.cargo\bin;C:\Program Files\LLVM\bin;C:\Program Files\NASM;C:\Program Files\Git\cmd;C:\Program Files\Python312;$FlutterBin;$env:PATH"

if (-not (Test-Path "$VcpkgRoot\installed")) {
  New-Item -ItemType Junction -Path "$VcpkgRoot\installed" -Target $VcpkgInstalled | Out-Null
}

function Invoke-InVsEnv([string]$cmd) {
  # vcvars64.bat overwrites VCPKG_ROOT with Visual Studio's own vcpkg, so set it afterwards
  cmd /c "call `"$vcvars`" >nul && set `"VCPKG_ROOT=$VcpkgRoot`" && $cmd"
  if ($LASTEXITCODE -ne 0) { throw "failed: $cmd" }
}

Invoke-InVsEnv 'cargo build --locked --features flutter --lib --release'
if (-not (Test-Path target\release\librustdesk.dll)) { throw 'cargo build did not produce librustdesk.dll' }
Push-Location flutter
Invoke-InVsEnv 'flutter pub get --enforce-lockfile'
Invoke-InVsEnv 'flutter build windows --release'
Pop-Location

$bundle = 'flutter\build\windows\x64\runner\Release'
if (-not (Test-Path "$bundle\handover.exe")) { throw "missing $bundle\handover.exe" }
$signArgs = @{ Subject = $SignSubject }
if ($SignThumbprint) { $signArgs.Thumbprint = $SignThumbprint }
if ($SignCreate) { $signArgs.Create = $true }
if ($Sign) {
  # The installer embeds these files, so they are signed before packing and the installer after.
  $inner = Get-ChildItem $bundle -Recurse -Include *.exe, *.dll | ForEach-Object { $_.FullName }
  & "$PSScriptRoot\sign-windows.ps1" -Files $inner @signArgs
}
Push-Location libs\portable
python -m pip install -r requirements.txt
Invoke-InVsEnv "python generate.py -f ..\..\$bundle -o . -e ..\..\$bundle\handover.exe"
Pop-Location
Copy-Item -Force target\release\rustdesk-portable-packer.exe handover-install.exe
if ($Sign) { & "$PSScriptRoot\sign-windows.ps1" -Files (Resolve-Path handover-install.exe).Path @signArgs }
Get-FileHash handover-install.exe -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLower())  handover-install.exe" } | Tee-Object SHA256SUMS.txt
Write-Host "built handover-install.exe"

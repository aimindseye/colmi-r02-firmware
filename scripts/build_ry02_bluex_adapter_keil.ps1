[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Workspace = "build\ry02-bluex-sdk3-ringcli-workspace",

    [Parameter(Mandatory = $false)]
    [string]$UV4Path = "C:\Keil_v5\UV4\UV4.exe",

    [Parameter(Mandatory = $false)]
    [string]$Target = "template",

    [Parameter(Mandatory = $false)]
    [string]$LogPath = ""
)

$ErrorActionPreference = "Stop"

$WorkspacePath = (Resolve-Path $Workspace).Path
$ProjectPath = Join-Path `
    $WorkspacePath `
    "examples\demo\ble_custom_profile\mdk\ble_custom_profile.uvprojx"

if (-not (Test-Path -LiteralPath $UV4Path -PathType Leaf)) {
    throw "UV4.exe not found: $UV4Path"
}

if (-not (Test-Path -LiteralPath $ProjectPath -PathType Leaf)) {
    throw "Keil project not found: $ProjectPath"
}

[xml]$ProjectXml = Get-Content -LiteralPath $ProjectPath
$TargetNode = $ProjectXml.Project.Targets.Target |
    Where-Object { $_.TargetName -eq $Target } |
    Select-Object -First 1

if ($null -eq $TargetNode) {
    throw "Target not found: $Target"
}

$CreateHexFile = [string]$TargetNode.TargetOption.TargetCommonOption.CreateHexFile
$OutputName = [string]$TargetNode.TargetOption.TargetCommonOption.OutputName

if ($CreateHexFile -ne "0") {
    throw "Refusing build: HEX generation is not disabled"
}

if ($OutputName -ne "ry02_ringcli_adapter_buildonly") {
    throw "Unexpected output name: $OutputName"
}

$MdkDirectory = Split-Path -Parent $ProjectPath

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $LogPath = Join-Path $MdkDirectory "ry02-bluex-armcc5-build.log"
}

$LogDirectory = Split-Path -Parent $LogPath
if (-not [string]::IsNullOrWhiteSpace($LogDirectory)) {
    New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null
}

Write-Host "RY02 BlueX ARMCC5 build-only gate"
Write-Host "Workspace: $WorkspacePath"
Write-Host "Project:   $ProjectPath"
Write-Host "Target:    $Target"
Write-Host "UV4:       $UV4Path"
Write-Host "Log:       $LogPath"
Write-Host "HEX:       disabled"
Write-Host "OTA:       none"
Write-Host "Device:    none"
Write-Host ""

& $UV4Path -r $ProjectPath -t $Target -o $LogPath
$BuildExitCode = $LASTEXITCODE

if (Test-Path -LiteralPath $LogPath) {
    Get-Content -LiteralPath $LogPath
}

if ($BuildExitCode -ne 0) {
    throw "uVision build failed with exit code $BuildExitCode"
}

$ObjectsDirectory = Join-Path $MdkDirectory "Objects"
$AxfPath = Join-Path $ObjectsDirectory "$OutputName.axf"

if (-not (Test-Path -LiteralPath $AxfPath -PathType Leaf)) {
    throw "Expected AXF not found: $AxfPath"
}

$Forbidden = Get-ChildItem `
    -LiteralPath $ObjectsDirectory `
    -Recurse `
    -File |
    Where-Object {
        $_.Extension -in @(".hex", ".bin", ".ota", ".38")
    }

if ($Forbidden.Count -gt 0) {
    $Names = ($Forbidden | ForEach-Object { $_.FullName }) -join ", "
    throw "Forbidden packaged/installable artifacts found: $Names"
}

Write-Host ""
Write-Host "uVision build command: PASS"
Write-Host "AXF: $AxfPath"
Write-Host "OTA packaging: none"
Write-Host "device action: none"

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:FusionVectorVersion = "0.58.0"
$script:FusionVectorArchive = "vector-$($script:FusionVectorVersion)-x86_64-pc-windows-msvc.zip"
$script:FusionVectorUri = "https://github.com/vectordotdev/vector/releases/download/v$($script:FusionVectorVersion)/$($script:FusionVectorArchive)"
$script:FusionVectorSha256 = "72bbedf4772302f7f67e7db2120fe5b42e39ae65873c895876fc2038050c10c5"
$script:FusionAgentServiceName = "FusionVectorAgent"
$script:FusionAgentDisplayName = "Fusion Windows Vector Agent"
$script:FusionAgentInstallRoot = Join-Path $env:ProgramFiles "Fusion Vector Agent"
$script:FusionAgentDataRoot = Join-Path $env:ProgramData "Fusion\Vector"
$script:FusionAgentBinary = Join-Path $script:FusionAgentInstallRoot "bin\vector.exe"
$script:FusionAgentConfig = Join-Path $script:FusionAgentDataRoot "vector.yaml"
$script:FusionAgentState = Join-Path $script:FusionAgentDataRoot "data"
$script:FusionAgentLogs = Join-Path $script:FusionAgentDataRoot "logs"
$script:FusionAgentMetadata = Join-Path $script:FusionAgentDataRoot "install.json"
$script:FusionAgentTemplate = Join-Path $PSScriptRoot "vector.yaml.template"

function Assert-FusionAgentAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session (Run as administrator)."
    }
}

function Assert-FusionSysmonPrerequisites {
    $service = Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Running" } |
        Select-Object -First 1
    if (-not $service) {
        throw "Sysmon is not running. Install and configure Sysmon separately, then retry; this script never installs Sysmon."
    }

    $channel = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if (-not $channel -or -not $channel.IsEnabled) {
        throw "The Microsoft-Windows-Sysmon/Operational event channel is missing or disabled."
    }
}

function Assert-FusionCollectorUrl {
    param([Parameter(Mandatory)][uri] $CollectorUrl)

    if (-not $CollectorUrl.IsAbsoluteUri) {
        throw "CollectorUrl must be an absolute URL."
    }
    if ($CollectorUrl.Scheme -notin @("http", "https")) {
        throw "CollectorUrl must use http or https."
    }
    if ($CollectorUrl.AbsolutePath -ne "/sysmon" -or $CollectorUrl.Query -or $CollectorUrl.Fragment) {
        throw "CollectorUrl must have the exact /sysmon path and no query or fragment (for example, http://fusion-host:8686/sysmon)."
    }
    if ($CollectorUrl.UserInfo) {
        throw "Do not put credentials in CollectorUrl. Fusion ingestion does not implement authentication."
    }
}

function ConvertTo-FusionYamlSingleQuoted {
    param([Parameter(Mandatory)][string] $Value)
    return $Value.Replace("'", "''")
}

function Write-FusionAgentConfiguration {
    param([Parameter(Mandatory)][uri] $CollectorUrl)

    Assert-FusionCollectorUrl -CollectorUrl $CollectorUrl
    if (-not (Test-Path -LiteralPath $script:FusionAgentTemplate)) {
        throw "Agent template was not found at $script:FusionAgentTemplate. Run this script from a complete Fusion checkout."
    }

    foreach ($directory in @($script:FusionAgentDataRoot, $script:FusionAgentState, $script:FusionAgentLogs)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }

    $content = [IO.File]::ReadAllText($script:FusionAgentTemplate)
    $content = $content.Replace("__FUSION_COLLECTOR_URL__", (ConvertTo-FusionYamlSingleQuoted $CollectorUrl.AbsoluteUri))
    $content = $content.Replace("__FUSION_DATA_DIR__", (ConvertTo-FusionYamlSingleQuoted $script:FusionAgentState))
    $content = $content.Replace("__FUSION_LOG_DIR__", (ConvertTo-FusionYamlSingleQuoted $script:FusionAgentLogs))
    [IO.File]::WriteAllText($script:FusionAgentConfig, $content, [Text.UTF8Encoding]::new($false))

    $metadata = [ordered]@{
        vector_version = $script:FusionVectorVersion
        collector_url = $CollectorUrl.AbsoluteUri
        configured_at_utc = [DateTime]::UtcNow.ToString("o")
        config_path = $script:FusionAgentConfig
    } | ConvertTo-Json
    [IO.File]::WriteAllText($script:FusionAgentMetadata, $metadata, [Text.UTF8Encoding]::new($false))

    # Well-known SIDs avoid localized account-name failures.
    & icacls.exe $script:FusionAgentDataRoot /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restrict permissions on $script:FusionAgentDataRoot."
    }
}

function Invoke-FusionVector {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Arguments)

    if (-not (Test-Path -LiteralPath $script:FusionAgentBinary)) {
        throw "Vector is not installed at $script:FusionAgentBinary. Run install.ps1 first."
    }
    & $script:FusionAgentBinary @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "vector.exe failed with exit code $LASTEXITCODE."
    }
}

function Get-FusionAgentService {
    return Get-Service -Name $script:FusionAgentServiceName -ErrorAction SilentlyContinue
}

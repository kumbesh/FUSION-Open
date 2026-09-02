[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = "Full receiver URL, for example http://192.168.56.1:8686/sysmon")]
    [uri] $CollectorUrl,
    [switch] $Force,
    [switch] $NoStart
)

. (Join-Path $PSScriptRoot "FusionAgent.Common.ps1")

Assert-FusionAgentAdministrator
Assert-FusionSysmonPrerequisites
Assert-FusionCollectorUrl -CollectorUrl $CollectorUrl
if ($CollectorUrl.Scheme -eq "http") {
    Write-Warning "Fusion v0.2 ingestion has no TLS or authentication. Use this URL only on an isolated, firewall-restricted lab network."
}

$existingService = Get-FusionAgentService
if ($existingService -and -not $Force) {
    throw "The $script:FusionAgentServiceName service already exists. Use configure.ps1 to change it, or rerun install.ps1 with -Force."
}

$downloadRoot = Join-Path ([IO.Path]::GetTempPath()) "fusion-vector-$([Guid]::NewGuid().ToString('N'))"
try {
    New-Item -ItemType Directory -Path $downloadRoot | Out-Null
    $archivePath = Join-Path $downloadRoot $script:FusionVectorArchive
    Write-Host "Downloading pinned Vector $script:FusionVectorVersion..."
    Invoke-WebRequest -Uri $script:FusionVectorUri -OutFile $archivePath
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath).Hash.ToLowerInvariant()
    if ($actualHash -ne $script:FusionVectorSha256) {
        throw "Vector archive checksum mismatch. Expected $script:FusionVectorSha256; received $actualHash."
    }

    $expandedPath = Join-Path $downloadRoot "expanded"
    Expand-Archive -LiteralPath $archivePath -DestinationPath $expandedPath
    $downloadedBinary = Get-ChildItem -LiteralPath $expandedPath -Filter "vector.exe" -Recurse |
        Select-Object -First 1
    if (-not $downloadedBinary) {
        throw "The Vector archive did not contain vector.exe."
    }

    if ($existingService) {
        Write-Host "Replacing the existing Fusion Vector service..."
        if (Test-Path -LiteralPath $script:FusionAgentBinary) {
            & $script:FusionAgentBinary service uninstall --name $script:FusionAgentServiceName --stop-timeout 30
        } else {
            & sc.exe delete $script:FusionAgentServiceName | Out-Null
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Could not remove the existing Fusion Vector service."
        }
        for ($attempt = 1; $attempt -le 20 -and (Get-FusionAgentService); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if (Get-FusionAgentService) {
            throw "The existing Fusion Vector service is still pending deletion. Wait a few seconds and retry."
        }
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $script:FusionAgentBinary) | Out-Null
    Copy-Item -LiteralPath $downloadedBinary.FullName -Destination $script:FusionAgentBinary -Force
    Write-FusionAgentConfiguration -CollectorUrl $CollectorUrl

    Write-Host "Validating the Windows Vector configuration..."
    Invoke-FusionVector validate --no-environment --config-yaml $script:FusionAgentConfig

    Write-Host "Installing the Windows service..."
    Invoke-FusionVector service install --name $script:FusionAgentServiceName --display-name $script:FusionAgentDisplayName --config-yaml $script:FusionAgentConfig
    & sc.exe failure $script:FusionAgentServiceName reset= 86400 actions= restart/5000/restart/15000/restart/30000 | Out-Null

    if (-not $NoStart) {
        Invoke-FusionVector service start --name $script:FusionAgentServiceName
    }

    Write-Host "Fusion Windows Vector agent installed."
    Write-Host "Collector: $($CollectorUrl.AbsoluteUri)"
    Write-Host "Configuration: $script:FusionAgentConfig"
} finally {
    if (Test-Path -LiteralPath $downloadRoot) {
        Remove-Item -LiteralPath $downloadRoot -Recurse -Force
    }
}

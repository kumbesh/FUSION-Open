[CmdletBinding()]
param([switch] $PurgeData)

. (Join-Path $PSScriptRoot "FusionAgent.Common.ps1")

Assert-FusionAgentAdministrator
$service = Get-FusionAgentService
if ($service) {
    if (Test-Path -LiteralPath $script:FusionAgentBinary) {
        Invoke-FusionVector service uninstall --name $script:FusionAgentServiceName --stop-timeout 30
    } else {
        if ($service.Status -ne "Stopped") {
            & sc.exe stop $script:FusionAgentServiceName | Out-Null
            $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
        }
        & sc.exe delete $script:FusionAgentServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not remove the Fusion Vector service."
        }
    }
    Write-Host "Removed the $script:FusionAgentServiceName service."
}

$installRoot = [IO.Path]::GetFullPath($script:FusionAgentInstallRoot).TrimEnd('\')
$programFilesRoot = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
if (-not $installRoot.StartsWith($programFilesRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove unexpected install path: $installRoot"
}
if (Test-Path -LiteralPath $installRoot) {
    Remove-Item -LiteralPath $installRoot -Recurse -Force
}

if ($PurgeData) {
    $dataRoot = [IO.Path]::GetFullPath($script:FusionAgentDataRoot).TrimEnd('\')
    $programDataRoot = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\'
    if (-not $dataRoot.StartsWith($programDataRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove unexpected data path: $dataRoot"
    }
    if (Test-Path -LiteralPath $dataRoot) {
        Remove-Item -LiteralPath $dataRoot -Recurse -Force
    }
    Write-Host "Removed agent configuration, logs, and buffered events from $dataRoot."
} else {
    Write-Host "Agent data was preserved at $script:FusionAgentDataRoot. Use -PurgeData to remove it."
}

Write-Host "Fusion Windows Vector agent uninstalled."

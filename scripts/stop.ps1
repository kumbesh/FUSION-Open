[CmdletBinding()]
param()

. (Join-Path $PSScriptRoot "Fusion.Common.ps1")

Assert-FusionEngine
Write-Host "Stopping Fusion without deleting data..."
Invoke-FusionCompose down --remove-orphans
Write-Host "Fusion stopped. Docker volumes were preserved."


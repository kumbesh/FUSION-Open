[CmdletBinding()]
param(
    [ValidateSet("WindowsPowerShell51", "PowerShell7Plus")]
    [string] $ExpectedRuntime
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Test {
    param(
        [Parameter(Mandatory = $true)][bool] $Condition,
        [Parameter(Mandatory = $true)][string] $Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-MatchCount {
    param(
        [Parameter(Mandatory = $true)][string] $Content,
        [Parameter(Mandatory = $true)][string] $Pattern,
        [Parameter(Mandatory = $true)][int] $ExpectedCount,
        [Parameter(Mandatory = $true)][string] $Description
    )

    $actualCount = [Text.RegularExpressions.Regex]::Matches(
        $Content,
        $Pattern,
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    ).Count
    Assert-Test ($actualCount -eq $ExpectedCount) "$Description expected $ExpectedCount match(es), found $actualCount."
}

function Get-EnvironmentValue {
    param(
        [Parameter(Mandatory = $true)][string] $Content,
        [Parameter(Mandatory = $true)][string] $Name
    )

    $match = [Text.RegularExpressions.Regex]::Match(
        $Content,
        "(?m)^$([Text.RegularExpressions.Regex]::Escape($Name))=(.+)$"
    )
    if (-not $match.Success) {
        throw "Generated .env is missing $Name."
    }
    return $match.Groups[1].Value.Trim()
}

$runtimeMajor = $PSVersionTable.PSVersion.Major
if ($ExpectedRuntime -eq "WindowsPowerShell51") {
    Assert-Test ($PSVersionTable.PSEdition -eq "Desktop" -and $runtimeMajor -eq 5) "Expected Windows PowerShell 5.1."
} elseif ($ExpectedRuntime -eq "PowerShell7Plus") {
    Assert-Test ($PSVersionTable.PSEdition -eq "Core" -and $runtimeMajor -ge 7) "Expected PowerShell 7 or later."
}

$repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "fusion-powershell-compat-$([Guid]::NewGuid().ToString('N'))"
$temporaryScripts = Join-Path $temporaryRoot "scripts"

try {
    [void](New-Item -ItemType Directory -Path $temporaryScripts)
    Copy-Item -LiteralPath (Join-Path $repositoryRoot "scripts\Fusion.Common.ps1") -Destination $temporaryScripts
    [IO.File]::WriteAllText(
        (Join-Path $temporaryRoot ".env.example"),
        "CLICKHOUSE_USER=fusion`nCLICKHOUSE_PASSWORD=CHANGE_ME_CLICKHOUSE`nGRAFANA_ADMIN_USER=admin`nGRAFANA_ADMIN_PASSWORD=CHANGE_ME_GRAFANA`nFUSION_BIND_ADDRESS=127.0.0.1`n"
    )

    . (Join-Path $temporaryScripts "Fusion.Common.ps1")

    $secrets = @(foreach ($index in 1..128) { New-FusionSecret })
    Assert-Test ($secrets.Count -eq 128) "Secret generation returned an unexpected sample count."
    Assert-Test (@($secrets | Sort-Object -Unique).Count -eq 128) "Secret generation produced a duplicate in the compatibility sample."
    foreach ($secret in $secrets) {
        Assert-Test ($secret -match '^[A-Za-z0-9_-]{32}$') "Secret output is not a 32-character Base64URL value."
        $decoded = [Convert]::FromBase64String($secret.Replace("-", "+").Replace("_", "/"))
        Assert-Test ($decoded.Length -eq 24) "Secret output does not contain 24 random bytes."
    }

    $initializationOutput = (& { Initialize-FusionEnvironment } *>&1 | Out-String)
    $environmentPath = Join-Path $temporaryRoot ".env"
    Assert-Test (Test-Path -LiteralPath $environmentPath) "Environment initialization did not create .env."

    $environmentContent = [IO.File]::ReadAllText($environmentPath)
    $clickHouseSecret = Get-EnvironmentValue $environmentContent "CLICKHOUSE_PASSWORD"
    $grafanaSecret = Get-EnvironmentValue $environmentContent "GRAFANA_ADMIN_PASSWORD"
    Assert-Test ($clickHouseSecret -match '^[A-Za-z0-9_-]{32}$') "Generated ClickHouse credential has an unexpected format."
    Assert-Test ($grafanaSecret -match '^[A-Za-z0-9_-]{32}$') "Generated Grafana credential has an unexpected format."
    Assert-Test ($clickHouseSecret -ne $grafanaSecret) "Generated service credentials must be independent."
    Assert-Test ($environmentContent -notmatch 'CHANGE_ME_') "Generated .env still contains a credential placeholder."
    Assert-Test ($initializationOutput -notmatch [Text.RegularExpressions.Regex]::Escape($clickHouseSecret)) "Environment initialization exposed the ClickHouse credential."
    Assert-Test ($initializationOutput -notmatch [Text.RegularExpressions.Regex]::Escape($grafanaSecret)) "Environment initialization exposed the Grafana credential."

    $beforeSecondInitialization = [Convert]::ToBase64String([IO.File]::ReadAllBytes($environmentPath))
    Initialize-FusionEnvironment
    $afterSecondInitialization = [Convert]::ToBase64String([IO.File]::ReadAllBytes($environmentPath))
    Assert-Test ($beforeSecondInitialization -eq $afterSecondInitialization) "Environment initialization replaced an existing .env file."

    $powerShellValidator = [IO.File]::ReadAllText((Join-Path $repositoryRoot "scripts\validate.ps1"))
    $shellValidator = [IO.File]::ReadAllText((Join-Path $repositoryRoot "scripts\validate.sh"))
    $powerShellDetectionValidator = [IO.File]::ReadAllText((Join-Path $repositoryRoot "scripts\validate-detections.ps1"))
    $shellDetectionValidator = [IO.File]::ReadAllText((Join-Path $repositoryRoot "scripts\validate-detections.sh"))
    $powerShellDeploy = [IO.File]::ReadAllText((Join-Path $repositoryRoot "scripts\deploy.ps1"))
    $shellDeploy = [IO.File]::ReadAllText((Join-Path $repositoryRoot "scripts\deploy.sh"))

    Assert-MatchCount $powerShellValidator '--async_insert=0\s+--multiquery' 3 "PowerShell migration fixtures"
    Assert-MatchCount $shellValidator '--async_insert=0\s+--multiquery' 3 "Shell migration fixtures"
    Assert-MatchCount $powerShellValidator '--async_insert=0\s+--query' 3 "PowerShell validation fixtures"
    Assert-MatchCount $shellValidator '--async_insert=0\s*\\?\s*--query' 3 "Shell validation fixtures"
    Assert-MatchCount $powerShellDetectionValidator '--async_insert=0\s+--query' 1 "PowerShell detection admin insert"
    Assert-MatchCount $shellDetectionValidator '--async_insert=0\s+--query' 1 "Shell detection admin insert"
    Assert-Test ($powerShellValidator -match '1`t35`t18`t8`t6') "PowerShell validation does not require the six-column evaluation-scope schema."
    Assert-Test ($shellValidator -match '1\\t35\\t18\\t8\\t6') "Shell validation does not require the six-column evaluation-scope schema."
    Assert-MatchCount $powerShellValidator '009_detection_candidate_cursor_v052\.sql' 1 "PowerShell candidate-cursor migration"
    Assert-MatchCount $shellValidator '009_detection_candidate_cursor_v052\.sql' 1 "Shell candidate-cursor migration"
    Assert-MatchCount $powerShellValidator '\$isolatedV052CursorMigration\s*\|' 1 "PowerShell idempotent candidate-cursor migration loop"
    Assert-MatchCount $shellValidator '--multiquery\s*<\s*"\$v052_cursor_migration_sql"' 2 "Shell idempotent candidate-cursor migration executions"
    Assert-Test ($powerShellValidator.Contains("isNull(candidate_cursor_time) AND candidate_cursor_uid = ''")) "PowerShell validation does not prove candidate cursor defaults preserve the scope sentinel."
    Assert-Test ($shellValidator.Contains("isNull(candidate_cursor_time) AND candidate_cursor_uid = ''")) "Shell validation does not prove candidate cursor defaults preserve the scope sentinel."
    Assert-Test ($powerShellValidator -match "getSetting\('wait_for_async_insert'\)") "PowerShell validation does not require acknowledged async inserts in the pinned environment."
    Assert-Test ($shellValidator -match "getSetting\('wait_for_async_insert'\)") "Shell validation does not require acknowledged async inserts in the pinned environment."
    Assert-Test ($powerShellDeploy -match 'up\s+--detach\s+--build\s+--force-recreate\s+--no-deps\s+fusion-detection-engine') "PowerShell deploy does not rebuild and recreate the detection engine during upgrades."
    Assert-Test ($shellDeploy -match 'up\s+--detach\s+--build\s+--force-recreate\s+--no-deps\s+fusion-detection-engine') "Shell deploy does not rebuild and recreate the detection engine during upgrades."

    foreach ($relativePath in @("docker-compose.yml", "vector\vector.yaml", "scripts\Fusion.Common.ps1", "scripts\lib.sh")) {
        $content = [IO.File]::ReadAllText((Join-Path $repositoryRoot $relativePath))
        Assert-Test ($content -notmatch '--async_insert=0') "Validation-only async insert override leaked into $relativePath."
    }
} finally {
    $temporaryPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
    if ($resolvedTemporaryRoot.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedTemporaryRoot) -like "fusion-powershell-compat-*") {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Deployment compatibility tests passed on $($PSVersionTable.PSEdition) PowerShell $($PSVersionTable.PSVersion)."

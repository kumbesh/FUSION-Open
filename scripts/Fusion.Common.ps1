Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:FusionRoot = Split-Path -Parent $PSScriptRoot
$script:FusionComposeFile = Join-Path $script:FusionRoot "docker-compose.yml"

function Get-FusionDocker {
    $desktopBin = Join-Path $env:ProgramFiles "Docker\Docker\resources\bin"
    $desktopCli = Join-Path $desktopBin "docker.exe"
    if ((Test-Path -LiteralPath $desktopCli) -and (($env:PATH -split ';') -notcontains $desktopBin)) {
        $env:PATH = "$desktopBin;$env:PATH"
    }

    $command = Get-Command docker -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    if (Test-Path -LiteralPath $desktopCli) {
        return $desktopCli
    }

    throw "Docker CLI was not found. Install and start Docker Desktop."
}

function New-FusionSecret {
    $bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(24)
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Initialize-FusionEnvironment {
    $envPath = Join-Path $script:FusionRoot ".env"
    if (Test-Path -LiteralPath $envPath) {
        return
    }

    $templatePath = Join-Path $script:FusionRoot ".env.example"
    $content = [IO.File]::ReadAllText($templatePath)
    $content = $content.Replace("CHANGE_ME_CLICKHOUSE", (New-FusionSecret))
    $content = $content.Replace("CHANGE_ME_GRAFANA", (New-FusionSecret))
    [IO.File]::WriteAllText($envPath, $content, [Text.UTF8Encoding]::new($false))
    Write-Host "Created .env with generated local passwords."
}

function Get-FusionSettings {
    Initialize-FusionEnvironment
    $settings = @{}
    foreach ($line in Get-Content -LiteralPath (Join-Path $script:FusionRoot ".env")) {
        if ($line -match '^\s*([^#][^=]*)=(.*)$') {
            $settings[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    return $settings
}

function Invoke-FusionCompose {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $ComposeArguments
    )

    $docker = Get-FusionDocker
    & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile @ComposeArguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE."
    }
}

function Assert-FusionEngine {
    $docker = Get-FusionDocker
    & $docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is installed but the engine is not running. Start Docker Desktop and try again."
    }
}

function Invoke-FusionMigrations {
    $migrationDirectory = Join-Path $script:FusionRoot "clickhouse\migrations"
    if (-not (Test-Path -LiteralPath $migrationDirectory)) {
        return
    }

    $settings = Get-FusionSettings
    $docker = Get-FusionDocker
    $migrations = Get-ChildItem -LiteralPath $migrationDirectory -Filter "*.sql" | Sort-Object Name
    foreach ($migration in $migrations) {
        Write-Host "Applying ClickHouse migration $($migration.Name)..."
        $sql = [IO.File]::ReadAllText($migration.FullName)
        $sql | & $docker compose --project-directory $script:FusionRoot -f $script:FusionComposeFile exec -T clickhouse clickhouse-client --user $settings.CLICKHOUSE_USER --password $settings.CLICKHOUSE_PASSWORD --multiquery
        if ($LASTEXITCODE -ne 0) {
            throw "ClickHouse migration $($migration.Name) failed."
        }
    }
}

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $VectorExecutable
)

$ErrorActionPreference = "Stop"
$templatePath = Join-Path $PSScriptRoot "vector.yaml.template"
$template = [IO.File]::ReadAllText($templatePath)

foreach ($requiredText in @(
    "type: windows_event_log",
    "Microsoft-Windows-Sysmon/Operational",
    "include_xml: true",
    "max_event_data_length: 0",
    "read_existing_events: false",
    "type: http",
    "method: bytes",
    "max_events: 1"
)) {
    if (-not $template.Contains($requiredText)) {
        throw "Windows agent template is missing required setting: $requiredText"
    }
}

foreach ($eventId in @(1, 3, 7, 11, 13, 22)) {
    if ($template -notmatch "(?m)^\s+- $eventId\r?$") {
        throw "Windows agent template does not select Sysmon Event ID $eventId."
    }
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) "fusion-agent-test-$([Guid]::NewGuid().ToString('N'))"
try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $renderedPath = Join-Path $temporaryRoot "vector.yaml"
    $rendered = $template.Replace("__FUSION_COLLECTOR_URL__", "http://192.0.2.10:8686/sysmon")
    $rendered = $rendered.Replace("__FUSION_DATA_DIR__", (Join-Path $temporaryRoot "data"))
    $rendered = $rendered.Replace("__FUSION_LOG_DIR__", (Join-Path $temporaryRoot "logs"))
    [IO.File]::WriteAllText($renderedPath, $rendered, [Text.UTF8Encoding]::new($false))

    & $VectorExecutable validate --no-environment --config-yaml $renderedPath
    if ($LASTEXITCODE -ne 0) {
        throw "Windows Vector configuration validation failed with exit code $LASTEXITCODE."
    }
    Write-Host "Windows Vector configuration is valid for Vector 0.58.0."
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

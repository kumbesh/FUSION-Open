[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $VectorExecutable
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "FusionAgent.Common.ps1")

function Assert-CollectorUrlRejected {
    param(
        [Parameter(Mandatory)][string] $Value,
        [Parameter(Mandatory)][string] $ExpectedMessage
    )

    $rejected = $false
    try {
        Assert-FusionCollectorUrl -CollectorUrl ([uri] $Value)
    } catch {
        $rejected = $true
        if ($_.Exception.Message -notlike "*$ExpectedMessage*") {
            throw "CollectorUrl '$Value' was rejected for the wrong reason: $($_.Exception.Message)"
        }
    }
    if (-not $rejected) {
        throw "CollectorUrl '$Value' should have been rejected."
    }
}

Assert-FusionCollectorUrl -CollectorUrl ([uri] "http://192.0.2.10:8686/sysmon")
Assert-FusionCollectorUrl -CollectorUrl ([uri] "https://192.0.2.10:9443/sysmon")
Assert-CollectorUrlRejected -Value "http://fusion-host:8686/sysmon" -ExpectedMessage "literal IPv4 address"
Assert-CollectorUrlRejected -Value "http://[2001:db8::10]:8686/sysmon" -ExpectedMessage "literal IPv4 address"
Assert-CollectorUrlRejected -Value "ftp://192.0.2.10:8686/sysmon" -ExpectedMessage "http or https"
Assert-CollectorUrlRejected -Value "http://192.0.2.10:8686/security" -ExpectedMessage "exact /sysmon path"
Assert-CollectorUrlRejected -Value "http://user@192.0.2.10:8686/sysmon" -ExpectedMessage "Do not put credentials"

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
    "max_events: 1",
    "exclude_fusion_collector_feedback",
    "com.docker.backend.exe",
    "__FUSION_COLLECTOR_HOST__",
    "__FUSION_COLLECTOR_PORT__",
    "__FUSION_AGENT_BINARY__",
    "__FUSION_DOCKER_DESKTOP_BINARY__"
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
    $rendered = $rendered.Replace("__FUSION_COLLECTOR_HOST__", '"192.0.2.10"')
    $rendered = $rendered.Replace("__FUSION_COLLECTOR_PORT__", "8686")
    $rendered = $rendered.Replace("__FUSION_AGENT_BINARY__", (ConvertTo-Json -InputObject (ConvertTo-FusionNormalizedExecutablePath $script:FusionAgentBinary) -Compress))
    $rendered = $rendered.Replace("__FUSION_DOCKER_DESKTOP_BINARY__", (ConvertTo-Json -InputObject (ConvertTo-FusionNormalizedExecutablePath $script:FusionDockerDesktopBinary) -Compress))
    $rendered = $rendered.Replace("__FUSION_DATA_DIR__", (Join-Path $temporaryRoot "data"))
    $rendered = $rendered.Replace("__FUSION_LOG_DIR__", (Join-Path $temporaryRoot "logs"))
    $feedbackRegressionTests = @'

tests:
  - name: drop_vector_collector_feedback
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_AGENT_TEST_BINARY__'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'true'
            Protocol: tcp
    no_outputs_from:
      - exclude_fusion_collector_feedback

  - name: retain_vector_when_only_destination_hostname_matches
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_AGENT_TEST_BINARY__'
            DestinationIp: '198.51.100.20'
            DestinationHostname: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'true'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.DestinationIp == "198.51.100.20"'

  - name: drop_docker_desktop_published_collector_feedback
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_DOCKER_DESKTOP_TEST_BINARY__'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'false'
            Protocol: tcp
    no_outputs_from:
      - exclude_fusion_collector_feedback

  - name: retain_user_writable_vector_lookalike
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: 'C:\Users\user\Fusion Vector Agent\bin\vector.exe'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'true'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.Image == "C:\\Users\\user\\Fusion Vector Agent\\bin\\vector.exe"'

  - name: retain_user_writable_docker_desktop_lookalike
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: 'C:\Users\user\Docker\Docker\resources\com.docker.backend.exe'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'false'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.Image == "C:\\Users\\user\\Docker\\Docker\\resources\\com.docker.backend.exe"'

  - name: retain_initiated_docker_desktop_collector_traffic
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_DOCKER_DESKTOP_TEST_BINARY__'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'true'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.Initiated == "true"'

  - name: retain_docker_desktop_collector_traffic_without_initiated
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_DOCKER_DESKTOP_TEST_BINARY__'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && !exists(.event_data.Initiated)'

  - name: retain_other_process_to_collector_port
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'true'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.Image == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"'

  - name: retain_docker_desktop_to_noncollector_host_same_port
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_DOCKER_DESKTOP_TEST_BINARY__'
            DestinationIp: '192.168.186.129'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'false'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.DestinationIp == "192.168.186.129"'

  - name: retain_docker_desktop_to_collector_other_port
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_DOCKER_DESKTOP_TEST_BINARY__'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '8687'
            Initiated: 'false'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.DestinationPort == "8687"'

  - name: retain_vector_to_noncollector_host_same_port
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_AGENT_TEST_BINARY__'
            DestinationIp: '192.168.186.129'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'true'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.DestinationIp == "192.168.186.129" && .event_data.DestinationPort == "8686"'

  - name: retain_vector_to_linux_ssh
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_AGENT_TEST_BINARY__'
            DestinationIp: '192.168.186.129'
            DestinationPort: '22'
            Initiated: 'true'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.DestinationIp == "192.168.186.129" && .event_data.DestinationPort == "22"'

  - name: retain_noninitiated_vector_collector_traffic
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_AGENT_TEST_BINARY__'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'false'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.Initiated == "false"'

  - name: retain_nonnetwork_vector_event
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 1
          event_data:
            Image: '__FUSION_AGENT_TEST_BINARY__'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'true'
            Protocol: tcp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 1'

  - name: retain_non_tcp_vector_collector_traffic
    inputs:
      - insert_at: exclude_fusion_collector_feedback
        type: log
        log_fields:
          event_id: 3
          event_data:
            Image: '__FUSION_AGENT_TEST_BINARY__'
            DestinationIp: '__FUSION_COLLECTOR_HOST__'
            DestinationPort: '__FUSION_COLLECTOR_PORT__'
            Initiated: 'true'
            Protocol: udp
    outputs:
      - extract_from: exclude_fusion_collector_feedback
        conditions:
          - type: vrl
            source: '.event_id == 3 && .event_data.Protocol == "udp"'
'@
    $feedbackRegressionTests = $feedbackRegressionTests.Replace("__FUSION_COLLECTOR_HOST__", "192.0.2.10")
    $feedbackRegressionTests = $feedbackRegressionTests.Replace("__FUSION_COLLECTOR_PORT__", "8686")
    $feedbackRegressionTests = $feedbackRegressionTests.Replace("__FUSION_AGENT_TEST_BINARY__", (ConvertTo-FusionYamlSingleQuoted $script:FusionAgentBinary))
    $feedbackRegressionTests = $feedbackRegressionTests.Replace("__FUSION_DOCKER_DESKTOP_TEST_BINARY__", (ConvertTo-FusionYamlSingleQuoted $script:FusionDockerDesktopBinary))
    $rendered += $feedbackRegressionTests
    [IO.File]::WriteAllText($renderedPath, $rendered, [Text.UTF8Encoding]::new($false))

    & $VectorExecutable validate --no-environment --config-yaml $renderedPath
    if ($LASTEXITCODE -ne 0) {
        throw "Windows Vector configuration validation failed with exit code $LASTEXITCODE."
    }
    & $VectorExecutable test --config-yaml $renderedPath
    if ($LASTEXITCODE -ne 0) {
        throw "Windows Vector configuration tests failed with exit code $LASTEXITCODE."
    }
    Write-Host "Windows Vector configuration is valid for Vector 0.58.0."
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

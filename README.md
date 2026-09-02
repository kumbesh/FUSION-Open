# Fusion

Fusion is a small, open-source security analytics lab for Windows telemetry. Fusion v0.2 can collect real Sysmon events with a native Windows Vector agent, while retaining the synthetic JSON workflow from v0.1. Both inputs use the same receiver, normalization transform, ClickHouse table, and Grafana dashboard.

```text
Windows Sysmon -> Windows Vector agent --HTTP--> Fusion Vector :8686
Synthetic JSON ----------------------------/          |
                                                      | VRL normalize
                                                      v
                                               ClickHouse -> Grafana :3000
```

## What is included

- Vector 0.58.0 HTTP receiver, native Windows agent, and shared VRL normalization
- ClickHouse 26.8.1.2041 with a partitioned, indexed event table
- Grafana 13.2.1 with ClickHouse data source 4.21.2
- A provisioned `Fusion Security Overview` dashboard
- Native Sysmon, Winlogbeat/ECS, and flat JSON field support
- Sysmon Event IDs 1, 3, 7, 11, 13, and 22 from the Windows agent
- Sample process creation, PowerShell, network connection, and DNS query events
- PowerShell and POSIX lifecycle scripts
- Vector unit tests and end-to-end validation

All service configuration, schema, dashboards, samples, and scripts live in this repository. Runtime state is held in named Docker volumes; local passwords are generated in the ignored `.env` file.

## Quick start

Requirements: Docker Desktop or Docker Engine with Docker Compose v2, at least 4 GB of available RAM, and ports `3000`, `8686`, and `8687` free on localhost.

Windows PowerShell:

```powershell
.\scripts\deploy.ps1
```

Linux or macOS:

```sh
./scripts/deploy.sh
```

The deploy script generates local passwords, pulls pinned images, waits for the services to become healthy, sends sample events, and validates the complete pipeline.

Open [http://localhost:3000](http://localhost:3000), sign in with the `GRAFANA_ADMIN_USER` and `GRAFANA_ADMIN_PASSWORD` values in `.env`, and select **Dashboards → Fusion → Fusion Security Overview**.

PowerShell can display the local Grafana credentials with:

```powershell
Get-Content .env | Select-String 'GRAFANA_ADMIN'
```

## Ingest Sysmon JSON

Send one JSON object per request to `POST /sysmon` with `Content-Type: application/json`:

```powershell
Invoke-WebRequest `
  -Uri http://localhost:8686/sysmon `
  -Method Post `
  -ContentType application/json `
  -InFile .\samples\sysmon\powershell-create.json
```

```sh
curl -i -H 'Content-Type: application/json' \
  --data-binary @samples/sysmon/powershell-create.json \
  http://localhost:8686/sysmon
```

A successful request returns HTTP `202`. Vector accepts these field layouts:

- Native/nested: `Event.System.EventID`, `Event.EventData.Image`
- Winlogbeat/ECS: `winlog.event_id`, `winlog.event_data.Image`, `host.name`
- Flat: `event_id`, `image`, `destination_ip`

Event IDs are classified as:

| Event ID | Fusion type | Dashboard use |
| ---: | --- | --- |
| 1 | `process_create` | Process creation and PowerShell execution |
| 3 | `network_connect` | Network connections and top destinations |
| 7 | `image_load` | Loaded image investigation |
| 11 | `file_create` | Created-file investigation |
| 13 | `registry_value_set` | Registry value investigation |
| 22 | `dns_query` | DNS query analytics |
| 4104 | `powershell_script` | Normalized script-block text when present |
| other | `sysmon_other` | Retained for investigation |

The original input is preserved in `raw_json`. For the Windows agent this includes Vector's parsed Windows event and the rendered source XML, enabling investigation and future reprocessing. Unknown or absent normalized fields receive safe empty defaults. Events that cannot be normalized are written to the Vector container log with `fusion_error=normalization_failed`.

## Connect a Windows Endpoint

The Windows endpoint must already have [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) installed and configured. Fusion deliberately does **not** install or reconfigure Sysmon. The active [Sysmon event-filtering policy](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files) must enable the event types you want to collect, including Event IDs 1, 3, 7, 11, 13, and 22. Image-load events (ID 7) can be high volume, so use a lab-appropriate Sysmon filter.

On the Windows endpoint, open an elevated PowerShell session and verify the prerequisites:

```powershell
Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
  Select-Object LogName, IsEnabled, RecordCount
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1,3,7,11,13,22
} -MaxEvents 10 | Select-Object TimeCreated, Id, MachineName
```

At least one Sysmon service must be `Running`, the channel must be enabled, and the final command should return events after normal endpoint activity. If DNS or network events are absent, confirm that those event types are enabled in the Sysmon configuration.

### Make the Fusion receiver reachable

The receiver remains bound to localhost by default. On the Fusion host, choose the IPv4 address of the host interface that is reachable from the isolated Windows VM, set it in `.env`, and redeploy:

```dotenv
FUSION_BIND_ADDRESS=<FUSION_HOST_LAB_INTERFACE_IP>
FUSION_INGEST_PORT=8686
```

```powershell
.\scripts\deploy.ps1
```

Do not set `FUSION_BIND_ADDRESS=0.0.0.0`. Binding a specific lab-interface address reduces exposure and keeps all existing v0.1 installations localhost-only unless this value is explicitly changed.

Networking depends on the VM platform:

- **Docker Desktop:** the published port is on the Windows host address selected by `FUSION_BIND_ADDRESS`, even though the containers run in Docker Desktop's Linux VM. Do not use a container or WSL-only address from the endpoint VM.
- **Hyper-V:** with an External switch, use the host address on that LAN. With an Internal switch, use the host's matching `vEthernet` adapter. The Default Switch uses a dynamic NAT subnet, so its address can change after restarts.
- **VMware:** use the physical adapter for bridged networking, the VMnet1 host adapter for host-only networking, or the VMnet8 host adapter for NAT. Host-only networking is preferred for an isolated lab.

On the Fusion host, list candidate interfaces with `Get-NetIPAddress -AddressFamily IPv4`. In the Windows VM, run `Get-NetIPConfiguration` and choose the Fusion host address on the VM's lab/NAT subnet. Confirm the selection from the VM before installing the agent:

```powershell
Test-NetConnection <FUSION_HOST_LAB_INTERFACE_IP> -Port 8686
```

Permit ingestion through Windows Firewall only from the test VM address or isolated lab subnet. Run this on the Fusion host as administrator, replacing every placeholder:

```powershell
New-NetFirewallRule `
  -DisplayName 'Fusion Sysmon ingestion - isolated lab' `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8686 `
  -LocalAddress <FUSION_HOST_LAB_INTERFACE_IP> `
  -RemoteAddress <WINDOWS_VM_IP_OR_LAB_CIDR> `
  -Profile Private
```

Fusion v0.2 ingestion on TCP 8686 has **no TLS and no authentication**. Never expose it directly to the public Internet or an untrusted network. Anyone who can reach it can submit events, and event contents are visible in transit.

### Install the Windows Vector agent

Clone or copy this repository to the Windows VM. In an elevated PowerShell session, run:

```powershell
.\agents\windows\install.ps1 `
  -CollectorUrl 'http://<FUSION_HOST_LAB_INTERFACE_IP>:8686/sysmon'
```

The installer downloads only the pinned Vector 0.58.0 Windows archive from the official GitHub release, verifies its SHA-256 checksum, renders the repository-managed agent template, restricts its data directory to SYSTEM and Administrators, validates the configuration, and installs the native `FusionVectorAgent` Windows service. It reads only new channel events by default; it does not replay the existing log.

Agent lifecycle commands are:

```powershell
.\agents\windows\configure.ps1 -CollectorUrl 'http://<FUSION_HOST_LAB_INTERFACE_IP>:8686/sysmon'
.\agents\windows\start.ps1
.\agents\windows\stop.ps1
.\agents\windows\status.ps1
.\agents\windows\uninstall.ps1
```

Uninstall preserves configuration, logs, checkpoints, and buffered events unless `-PurgeData` is supplied. The agent stores its rendered configuration and disk buffer under `C:\ProgramData\Fusion\Vector` and its executable under `C:\Program Files\Fusion Vector Agent`.

Generate safe activity after the agent starts—for example, launch a process and run `Resolve-DnsName example.com`—then verify storage from the Fusion host:

```powershell
$settings = @{}
Get-Content .env | ForEach-Object {
  if ($_ -match '^([^#][^=]*)=(.*)$') { $settings[$matches[1]] = $matches[2] }
}
docker compose exec clickhouse clickhouse-client `
  --user $settings.CLICKHOUSE_USER `
  --password $settings.CLICKHOUSE_PASSWORD `
  --query "SELECT event_id, event_type, computer, count() FROM fusion.sysmon_events WHERE event_id IN (1,3,22) GROUP BY event_id, event_type, computer ORDER BY event_id"
```

For detailed endpoint instructions and troubleshooting, see [agents/windows/README.md](agents/windows/README.md).

## Dashboard

The provisioned dashboard contains:

- Total, process creation, PowerShell, and network event counters
- Security activity over time by event type
- Top network destinations, external destinations, executed processes, and DNS queries
- Sysmon event distribution by Event ID
- Recent process creation details
- PowerShell command-line details
- Source and destination network connection details
- A multi-select computer filter

PowerShell execution is derived from Sysmon Event ID 1 when `Image` contains `powershell.exe` or `pwsh.exe`.

## Lifecycle commands

| Action | PowerShell | POSIX shell |
| --- | --- | --- |
| Deploy or update | `.\scripts\deploy.ps1` | `./scripts/deploy.sh` |
| Stop, preserve data | `.\scripts\stop.ps1` | `./scripts/stop.sh` |
| Validate end to end | `.\scripts\validate.ps1` | `./scripts/validate.sh` |
| Delete data and redeploy | `.\scripts\reset.ps1` | `./scripts/reset.sh` |
| Non-interactive reset | `.\scripts\reset.ps1 -Force` | `./scripts/reset.sh --force` |

Useful direct commands:

```sh
docker compose ps
docker compose logs -f vector
docker compose logs -f clickhouse
docker compose logs -f grafana
```

The reset command permanently removes the Fusion Docker volumes. The stop command does not.

## Query ClickHouse

ClickHouse is intentionally not published to the host. Query it through the container:

```powershell
$settings = @{}
Get-Content .env | ForEach-Object {
  if ($_ -match '^([^#][^=]*)=(.*)$') { $settings[$matches[1]] = $matches[2] }
}
docker compose exec clickhouse clickhouse-client `
  --user $settings.CLICKHOUSE_USER `
  --password $settings.CLICKHOUSE_PASSWORD `
  --query "SELECT event_type, count() FROM fusion.sysmon_events GROUP BY event_type"
```

The table is partitioned monthly, ordered for time-based security investigation, and automatically expires events after 90 days. Change the `TTL` in `clickhouse/init/001_schema.sql` before the first deployment, or apply an `ALTER TABLE` to an existing lab.

## Repository layout

```text
agents/windows/                          Native Vector agent configuration and lifecycle scripts
clickhouse/init/                         ClickHouse schema for fresh installations
clickhouse/migrations/                   Idempotent upgrades for existing volumes
grafana/dashboards/                      Versioned dashboard JSON
grafana/provisioning/                    Dashboard and data-source provisioning
samples/sysmon/                          v0.1 synthetic test events
samples/windows-agent/                   Native Windows-agent-shaped test events
scripts/                                 Deploy, stop, reset, and validate helpers
vector/vector.yaml                       Receiver, normalization, buffering, tests
docker-compose.yml                       Pinned service topology
```

## Security boundaries

Fusion is a local lab, not an internet-facing deployment. Grafana, ingestion, and the Vector health API bind to `127.0.0.1` by default; ClickHouse is reachable only on the private Compose network. Only the ingestion address can be explicitly changed with `FUSION_BIND_ADDRESS` for an isolated Windows lab VM. The HTTP receiver does not use TLS or authentication. Never expose TCP 8686 directly to the public Internet, and restrict any lab binding with a host firewall rule scoped to the test VM or isolated subnet.

Do not send real credentials or sensitive production telemetry to the included sample environment. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Development

Validate configuration after changes:

```powershell
.\scripts\validate.ps1
```

The validator checks both supported bind modes, compiles the collector configuration, runs all VRL tests, verifies the migrated ClickHouse schema and container health, sends tagged v0.1 and Windows-agent-shaped samples, asserts Event IDs 1, 3, and 22, runs the dashboard telemetry queries, checks the Grafana data source, and confirms dashboard provisioning. Validate the Windows-only source configuration with `agents/windows/test-config.ps1` and the Vector 0.58.0 Windows executable.

Contributions are welcome under the MIT license.

# Fusion

Fusion is a small, open-source security analytics lab for Windows telemetry. It accepts Sysmon JSON over HTTP, normalizes common field layouts with Vector, stores the result in ClickHouse, and ships with a provisioned Grafana security dashboard.

```text
Sysmon JSON  ->  Vector :8686  ->  ClickHouse  ->  Grafana :3000
                   |               |
                   | normalize     +-- 90-day MergeTree storage
                   +-- disk buffer
```

## What is included

- Vector 0.58.0 HTTP receiver and VRL normalization
- ClickHouse 26.8.1.2041 with a partitioned, indexed event table
- Grafana 13.2.1 with ClickHouse data source 4.21.2
- A provisioned `Fusion Security Overview` dashboard
- Native Sysmon, Winlogbeat/ECS, and flat JSON field support
- Sample process creation, PowerShell, and network connection events
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
| 4104 | `powershell_script` | Normalized script-block text when present |
| other | `sysmon_other` | Retained for investigation |

The original input is preserved in `raw_json`. Unknown or absent normalized fields receive safe empty defaults. Events that cannot be normalized are written to the Vector container log with `fusion_error=normalization_failed`.

## Dashboard

The provisioned dashboard contains:

- Total, process creation, PowerShell, and network event counters
- Security activity over time by event type
- Top network destinations
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
clickhouse/init/                         ClickHouse schema
grafana/dashboards/                      Versioned dashboard JSON
grafana/provisioning/                    Dashboard and data-source provisioning
samples/sysmon/                          Safe synthetic test events
scripts/                                 Deploy, stop, reset, and validate helpers
vector/vector.yaml                       Receiver, normalization, buffering, tests
docker-compose.yml                       Pinned service topology
```

## Security boundaries

Fusion is a local lab, not an internet-facing deployment. Grafana, ingestion, and the Vector health API bind only to `127.0.0.1`; ClickHouse is reachable only on the private Compose network. The HTTP receiver does not use TLS or authentication. Do not change the bind addresses or expose the ports to an untrusted network without adding a TLS reverse proxy, authentication, network controls, and secret management.

Do not send real credentials or sensitive production telemetry to the included sample environment. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Development

Validate configuration after changes:

```powershell
.\scripts\validate.ps1
```

The validator checks Compose syntax, compiles Vector configuration, runs VRL unit tests, verifies container health, sends tagged samples, asserts normalized ClickHouse results, checks the Grafana data source, and confirms dashboard provisioning.

Contributions are welcome under the MIT license.


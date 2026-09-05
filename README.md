# Fusion

Fusion is a small, open-source security analytics lab for endpoint and network-security telemetry. Fusion v0.5 adds a standalone post-ingestion detection engine to the proven v0.4 multi-source data plane. Every input still uses the same Vector normalization layer and backward-compatible ClickHouse event table.

## What FUSION-Open does

```text
Windows Sysmon ─┐
Linux auditd ───┼─> Vector ─> ClickHouse ─> Detection Engine ─> Grafana
Suricata EVE ───┘                         │
                                         └─ Sigma + MITRE ATT&CK
```

## Screenshots

### Fusion Detections

![Fusion Detections](docs/images/fusion-detections.png)

### Security Sources

![Security Sources](docs/images/security-sources.png)

## What is included

- Vector 0.58.0 HTTP and TCP/UDP syslog receivers, native endpoint agents, and shared VRL normalization
- ClickHouse 26.8.1.2041 with a partitioned, indexed event table
- Grafana 13.2.1 with ClickHouse data source 4.21.2
- Provisioned `Fusion Security Overview`, `Fusion Security Sources`, and `Fusion Detections` dashboards
- A Python 3.12 service evaluating a strict, repository-managed Sigma subset after ingestion
- Native Sysmon, Winlogbeat/ECS, flat JSON, Linux auditd, and native journald field support
- Sysmon Event IDs 1, 3, 7, 11, 13, and 22 from the Windows agent
- Sample process creation, PowerShell, network connection, and DNS query events
- PowerShell and POSIX lab lifecycle scripts, plus endpoint-agent lifecycle scripts
- Vector unit tests and end-to-end validation

All service configuration, schema, dashboards, samples, and scripts live in this repository. Runtime state is held in named Docker volumes; local passwords are generated in the ignored `.env` file.

## Quick start

Requirements: Docker Desktop or Docker Engine with Docker Compose v2, at least 4 GB of available RAM, and ports `3000`, `8686`, `8687`, and TCP/UDP `5514` free on localhost.

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

The original input is preserved in `raw_json`. For the Windows agent this includes Vector's parsed Windows event and the rendered source XML, enabling investigation and future reprocessing. Linux audit records and full selected journald objects are preserved the same way. Unknown or absent normalized fields receive safe empty defaults. Events that cannot be normalized are written to the Vector container log with `fusion_error=normalization_failed`.

### Common event model

The existing `fusion.sysmon_events` table remains in place for backward compatibility. In addition to the v0.3 common endpoint fields, v0.4 adds `device_name`, `vendor`, `product`, `event_kind`, `ingestion_protocol`, `ingestion_path`, `source_address`, `original_format`, `network_direction`, `rule_id`, `signature`, `signature_id`, `url`, `domain`, `syslog_facility`, and `syslog_application`. v0.5 adds a materialized `event_uid` used for deterministic detection identity. Transport peer metadata is deliberately separate from event-level `source_ip` and `destination_ip`.

`scripts/deploy.ps1` and `scripts/deploy.sh` apply every idempotent migration, including `clickhouse/migrations/005_detection_engine_v05.sql`, before recreating the services. The validator upgrades isolated v0.2, v0.3, and v0.4 table shapes and proves that Windows, Linux, Suricata, syslog, and raw event data survive. Existing named volumes are never reset during deployment.

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

The receiver remains bound to localhost by default. On the Fusion host, choose the IPv4 address of the host interface that is reachable from the isolated endpoint VM, set it in `.env`, and redeploy:

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

On the Fusion host, list candidate interfaces with `Get-NetIPAddress -AddressFamily IPv4`. In a Windows VM, run `Get-NetIPConfiguration`; in a Linux VM, use `ip route`. Choose the Fusion host address on the VM's lab/NAT subnet and confirm it before installing an agent:

```powershell
Test-NetConnection <FUSION_HOST_LAB_INTERFACE_IP> -Port 8686
```

Permit ingestion through Windows Firewall only from the test VM address or isolated lab subnet. Run this on the Fusion host as administrator, replacing every placeholder:

```powershell
New-NetFirewallRule `
  -DisplayName 'Fusion endpoint ingestion - isolated lab' `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8686 `
  -LocalAddress <FUSION_HOST_LAB_INTERFACE_IP> `
  -RemoteAddress <WINDOWS_VM_IP_OR_LAB_CIDR> `
  -Profile Private
```

Fusion HTTP ingestion on TCP 8686 has **no TLS and no authentication**. Never expose it directly to the public Internet or an untrusted network. Anyone who can reach it can submit events, and event contents are visible in transit.

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

## Connect a Linux Endpoint

Fusion v0.3 initially targets Ubuntu 24.04 LTS using Vector 0.58.0's native `file` and `journald` sources. Ubuntu 24.04 remains the configuration/CI baseline; real endpoint acceptance was completed on an x86_64 Ubuntu 26.04 LTS VMware VM on 2026-09-03. The Linux agent reads new records from `/var/log/audit/audit.log` and selected SSH, sudo, su, systemd, and logind journal sources. It sends both streams to the existing collector on `POST /linux`; it does not create a second storage pipeline or schema.

Fusion deliberately does **not** install, start, or modify auditd. On the Linux VM, verify the prerequisites first:

```sh
dpkg-query --show auditd
command -v auditctl
sudo systemctl is-active auditd.service
sudo auditctl -s
sudo test -r /var/log/audit/audit.log
sudo ausearch -m EXECVE,SYSCALL,USER_CMD,USER_LOGIN,USER_AUTH,USER_ACCT,CRED_ACQ,CRED_DISP --start recent
sudo journalctl --boot --unit ssh.service --unit sshd.service --unit systemd-logind.service --lines 20
```

The audit search can be empty until the VM's existing audit policy produces those records. Example audit rules in [agents/linux/README.md](agents/linux/README.md) are clearly labeled **LAB/TEST** and are never applied by Fusion.

Use the same isolated interface and restricted TCP 8686 firewall rule described in [Make the Fusion receiver reachable](#make-the-fusion-receiver-reachable). From the Linux VM, determine its route to the Fusion host and verify the selected address:

```sh
ip route get <FUSION_HOST_LAB_IP>
nc -vz <FUSION_HOST_LAB_IP> 8686
```

Do not disable a firewall to make this work. When Fusion itself runs on a Linux host using UFW, an example narrowly scoped rule is:

```sh
sudo ufw allow from <LINUX_VM_IP_OR_LAB_CIDR> to <FUSION_HOST_LAB_IP> port 8686 proto tcp
sudo ufw status numbered
```

Use the equivalent source-scoped rule for firewalld or nftables. If Fusion runs on Windows, use the restricted Windows Firewall rule above and include only the Linux VM address or isolated lab subnet.

Copy or clone the repository to the Ubuntu VM, then install the agent as root:

```sh
cd agents/linux
sudo ./install.sh http://<FUSION_HOST_LAB_IP>:8686/linux
./status.sh
```

The installer downloads the pinned official Vector archive for x86_64 or aarch64, verifies its SHA-256 digest, validates the configuration, installs a hardened systemd service, enables it at boot, and starts it. The agent reads only new audit and journal records on first use. Lifecycle commands are:

```sh
sudo ./configure.sh http://<FUSION_HOST_LAB_IP>:8686/linux
sudo ./start.sh
sudo ./stop.sh
./status.sh
sudo ./uninstall.sh
```

Generate harmless lab activity such as `/usr/bin/printf 'fusion-test\n'` and `sudo /usr/bin/id`, then verify on the Fusion host:

```sh
set -a
. ./.env
set +a
docker compose exec clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT event_time, host_name, source_type, event_action, process_path, user_name, outcome FROM fusion.sysmon_events WHERE platform = 'linux' ORDER BY event_time DESC LIMIT 25"
```

Open Grafana, choose `linux` in the **Platform** filter, and inspect Linux process, authentication, sudo, and source-type panels. The repository's fixtures remain synthetic validation and are not substitutes for endpoint testing. Fusion v0.3 additionally passed the complete Ubuntu 26.04 VMware path—Linux VM, Vector agent, collector, normalization, ClickHouse, and Grafana—with real process, sudo, successful and failed SSH authentication, and systemd activity. Other distributions and architectures remain untested until separately accepted.

Detailed audit prerequisites, LAB/TEST examples, agent paths, security controls, and troubleshooting are in [agents/linux/README.md](agents/linux/README.md).

## Connect a Security Tool

Fusion v0.4 accepts a generic JSON envelope at `POST /security`. Put source identity outside the vendor event so the transport metadata remains stable while the complete original object stays available in `raw_json`:

Supported connection patterns are:

1. HTTP JSON to `/security`.
2. RFC 3164/5424 syslog over TCP.
3. RFC 3164/5424 syslog over UDP.
4. File collection through a local Vector shipper, as demonstrated by Suricata EVE.
5. Future REST API connectors that checkpoint and forward the same generic envelope; this is design-only in v0.4.

```json
{
  "vendor": "ExampleCo",
  "product": "Example IDS",
  "source_type": "example_json",
  "platform": "network",
  "device_name": "sensor-01",
  "event": {
    "timestamp": "2026-09-03T12:00:00.000Z",
    "event_action": "network_alert",
    "source_ip": "192.0.2.20",
    "destination_ip": "198.51.100.40",
    "signature": "Example rule"
  }
}
```

```sh
curl -i -H 'Content-Type: application/json' \
  --data-binary @samples/security-tools/suricata-alert.json \
  http://localhost:8686/security
```

The JSON event is limited to 1 MiB by the v0.4 normalizer; oversized events are rejected from storage and logged by the collector. The ClickHouse sink uses a bounded 256 MiB disk buffer with backpressure. If ClickHouse is unavailable, Vector retries for a bounded request window and then retains events in the disk buffer; when the buffer fills, inputs block instead of consuming unbounded memory.

Generic RFC 3164 and RFC 5424 syslog is accepted over TCP and UDP. Defaults are secure and local-only:

```dotenv
FUSION_SYSLOG_BIND_ADDRESS=127.0.0.1
FUSION_SYSLOG_TCP_PORT=5514
FUSION_SYSLOG_UDP_PORT=5514
```

To receive from an isolated VM or appliance, set `FUSION_SYSLOG_BIND_ADDRESS` to the specific Fusion host interface reachable from that device—never `0.0.0.0`—then redeploy. The Docker Desktop, Hyper-V, and VMware address-selection guidance in [Make the Fusion receiver reachable](#make-the-fusion-receiver-reachable) applies to syslog too. Permit TCP and/or UDP 5514 only from the individual test device or lab subnet. On a Windows Fusion host, for example:

```powershell
New-NetFirewallRule -DisplayName 'Fusion syslog TCP - isolated lab' `
  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5514 `
  -LocalAddress <FUSION_HOST_LAB_IP> -RemoteAddress <TEST_DEVICE_IP_OR_LAB_CIDR> -Profile Private
New-NetFirewallRule -DisplayName 'Fusion syslog UDP - isolated lab' `
  -Direction Inbound -Action Allow -Protocol UDP -LocalPort 5514 `
  -LocalAddress <FUSION_HOST_LAB_IP> -RemoteAddress <TEST_DEVICE_IP_OR_LAB_CIDR> -Profile Private
```

Syslog messages are capped at 64 KiB and TCP is capped at 100 simultaneous connections. Unknown but syntactically valid syslog is retained as `generic_syslog`; parsed application, facility, severity, hostname, message ID, peer address, and the complete parsed object are preserved. TCP/UDP syslog is plaintext and unauthenticated. HTTP 8686 also has no TLS or authentication. Never expose any ingestion port directly to the public Internet or an untrusted network. A future hardened transport should add HTTPS with tokens or mTLS and syslog over TLS; those controls are not present in v0.4.

When adding a future file or HTTP source, extend `normalize_security` and the common event model instead of creating a vendor table or parallel collector. The planned API-polling contract—cursor state, rate limits, retry/backoff, deduplication, and secret handling—is documented in [docs/api-connectors.md](docs/api-connectors.md); v0.4 deliberately does not implement an API connector.

## Suricata Integration

Fusion does **not** install, start, reconfigure, or upgrade Suricata. A Suricata sensor must already be producing newline-delimited EVE JSON at `/var/log/suricata/eve.json` (or another explicit absolute path). The initial normalizer supports EVE `alert`, `dns`, `http`, `tls`, and `flow` records.

On the sensor, verify the prerequisite without changing it:

```sh
sudo systemctl is-active suricata.service
sudo test -r /var/log/suricata/eve.json
sudo tail -n 5 /var/log/suricata/eve.json
sudo grep -m 1 -E '"event_type":"(alert|dns|http|tls|flow)"' /var/log/suricata/eve.json
```

First make HTTP 8686 reachable only from the Suricata sensor using `FUSION_BIND_ADDRESS` and the restricted firewall guidance above. From the sensor, verify the route and port, then install the repository-managed Vector shipper:

```sh
ip route get <FUSION_HOST_LAB_IP>
nc -vz <FUSION_HOST_LAB_IP> 8686
cd integrations/suricata
sudo sh ./install.sh http://<FUSION_HOST_LAB_IP>:8686/security /var/log/suricata/eve.json <SENSOR_NAME>
sh ./status.sh
```

Lifecycle commands are:

```sh
sudo sh ./configure.sh http://<FUSION_HOST_LAB_IP>:8686/security /var/log/suricata/eve.json <SENSOR_NAME>
sudo sh ./start.sh
sudo sh ./stop.sh
sh ./status.sh
sudo sh ./uninstall.sh
```

The shipper reads only new EVE lines on first use, checkpoints file offsets, follows normal Suricata log rotation, wraps each EVE object with Fusion source metadata, and sends it to `/security`. Use a literal Fusion host IP in the collector URL. The generated configuration discards EVE records whose destination IP and port are the collector itself; this prevents a sensor monitoring its own outbound Vector traffic from creating a recursive ingestion loop. Its 1 MiB line/request bounds and 256 MiB disk buffer prevent unbounded growth. Do not manually truncate `eve.json` or delete the checkpoint directory while buffered telemetry matters.

This remains a single-node lab: there is no high availability, load balancing, or broker. UDP can lose messages under network or receiver pressure, and once a Vector disk buffer is full its input blocks. Monitor buffer use and ClickHouse health, size retention for the lab, and prefer TCP/HTTP when delivery matters.

Verify stored real telemetry on the Fusion host:

```sh
set -a; . ./.env; set +a
docker compose exec clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT event_time, device_name, event_action, signature, domain, url, source_ip, destination_ip FROM fusion.sysmon_events WHERE product = 'Suricata' ORDER BY event_time DESC LIMIT 25"
```

Open **Dashboards → Fusion → Fusion Security Sources** and select `Suricata` in the Product filter. The files under `samples/security-tools/` prove configuration and normalization only; they are synthetic and do not satisfy real Suricata acceptance. Real acceptance was completed on an x86_64 Ubuntu 26.04 VMware sensor running Suricata 8.0.3 on 2026-09-03 UTC, including alert, DNS, HTTP, TLS, flow, raw-event, ClickHouse, and Grafana verification. See [docs/suricata-acceptance.md](docs/suricata-acceptance.md) for the evidence and [integrations/suricata/README.md](integrations/suricata/README.md) for installation and troubleshooting.

## Fusion Detection Engine

The v0.5 detection service operates after ClickHouse ingestion. It reads bounded batches of normalized events, evaluates nine curated Sigma YAML rules in Python, and writes matches to `fusion.detections`. Vector contains no rule logic, and stopping or failing the detection service does not interrupt telemetry ingestion.

The engine provides:

- A persistent ClickHouse checkpoint and configurable late-event lookback
- Deterministic `SHA-256(rule_id + source_event_uid)` detection IDs
- Idempotent replay and restart behavior
- Focused evidence containing matched selections, fields, and source event UID
- Sigma severity and MITRE ATT&CK metadata mapping
- Exponential ClickHouse retry/backoff and bounded batch sizes
- No host port, remote rule download, or runtime Internet dependency

Configuration defaults are in `.env.example`:

```dotenv
FUSION_DETECTION_POLL_SECONDS=10
FUSION_DETECTION_LOOKBACK_SECONDS=120
FUSION_DETECTION_BATCH_SIZE=1000
FUSION_DETECTION_LOG_LEVEL=INFO
```

Validate every rule without running detections:

```powershell
docker compose run --rm --no-deps fusion-detection-engine validate-rules
```

Dry-run one rule against a bounded ClickHouse window without writing detections:

```powershell
docker compose run --rm --no-deps fusion-detection-engine `
  test-rule /rules/windows/encoded-powershell.yml --hours 24 --limit 1000
```

Open **Dashboards → Fusion → Fusion Detections** to view severity, status, rule, platform, source, host, user, IP, and MITRE views. Detection status defaults to `new`; the schema reserves `acknowledged` and `closed`, but v0.5 intentionally has no state-management UI.

### Supported Sigma subset

Fusion supports exact matches, lists, `contains`, `startswith`, `endswith`, `exists`, AND/OR/NOT, parentheses, `1 of selection_*`, and `all of selection_*`. Field and logsource mappings are allowlisted in `detections/mappings/sigma_fields.yml`. Unknown fields, arbitrary SQL, unsupported modifiers, correlation, aggregation, threshold expressions, and `timeframe` fail validation instead of being approximated.

See [detections/README.md](detections/README.md) for the complete field mapping, compiler boundary, rule-testing workflow, checkpoint/deduplication design, security controls, and performance limits. The manual real-endpoint gate is tracked separately in [docs/detection-acceptance.md](docs/detection-acceptance.md).

### Writing a Fusion Detection Rule

Use standard Sigma YAML under the platform directory and only mapped normalized fields. A Windows example:

```yaml
title: Encoded PowerShell Command
id: example-windows-encoded-powershell
logsource:
  product: windows
  service: sysmon
detection:
  process:
    EventID: 1
    Image|endswith: '\powershell.exe'
  flag:
    CommandLine|contains: ' -enc '
  condition: process and flag
tags:
  - attack.execution
  - attack.t1059.001
level: high
```

A network example:

```yaml
title: Selected Dynamic DNS Query
id: example-network-dynamic-dns
logsource:
  product: network
  service: suricata
detection:
  selection:
    Action: dns_query
    QueryName|endswith: '.duckdns.org'
  condition: selection
level: low
```

Give every rule a stable unique ID, conservative severity, false-positive guidance, and positive plus negative fixtures. Detection results are analytical signals, not proof that activity is malicious.

## Dashboard

The provisioned multi-platform dashboard contains:

- Total, process creation, PowerShell, and network event counters
- Security activity over time by event type
- Top network destinations, external destinations, executed processes, and DNS queries
- Sysmon event distribution by Event ID
- Recent process creation details
- PowerShell command-line details
- Source and destination network connection details
- Platform and host filters
- Event volume by platform and source type
- Linux process execution, authentication success/failure, failed-login, and sudo views
- Vendor, product, source type, and ingestion-protocol volumes
- Suricata alerts, signatures, source/destination IPs, DNS, HTTP, TLS, and flow activity
- Generic TCP/UDP syslog volume and recent security-tool events
- Detection totals, high/critical and new status counters, severity/rule/source/host breakdowns, MITRE tactics and techniques, and recent evidence

PowerShell execution is derived from Sysmon Event ID 1 when `Image` contains `powershell.exe` or `pwsh.exe`.

## Lifecycle commands

| Action | PowerShell | POSIX shell |
| --- | --- | --- |
| Deploy or update | `.\scripts\deploy.ps1` | `./scripts/deploy.sh` |
| Stop, preserve data | `.\scripts\stop.ps1` | `./scripts/stop.sh` |
| Validate end to end | `.\scripts\validate.ps1` | `./scripts/validate.sh` |
| Validate detections | `.\scripts\validate-detections.ps1` | `./scripts/validate-detections.sh` |
| Delete data and redeploy | `.\scripts\reset.ps1` | `./scripts/reset.sh` |
| Non-interactive reset | `.\scripts\reset.ps1 -Force` | `./scripts/reset.sh --force` |

Useful direct commands:

```sh
docker compose ps
docker compose logs -f vector
docker compose logs -f clickhouse
docker compose logs -f grafana
docker compose logs -f fusion-detection-engine
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
agents/windows/                          Native Windows Vector agent and lifecycle scripts
agents/linux/                            Native Linux Vector agent, systemd unit, and lifecycle scripts
integrations/suricata/                   EVE JSON shipper, hardened service, and lifecycle scripts
detections/engine/                       Python 3.12 polling engine and CLI
detections/rules/                        Curated repository-managed Sigma YAML
detections/mappings/                     Sigma field/logsource and MITRE mappings
detections/tests/                        Compiler, security, identity, and platform tests
clickhouse/init/                         ClickHouse schema for fresh installations
clickhouse/migrations/                   Idempotent upgrades for existing volumes
grafana/dashboards/                      Versioned dashboard JSON
grafana/provisioning/                    Dashboard and data-source provisioning
samples/sysmon/                          v0.1 synthetic test events
samples/windows-agent/                   Native Windows-agent-shaped test events
samples/linux-agent/                     Linux auditd/journald validation fixtures
samples/security-tools/                  Suricata EVE and RFC 3164/5424 validation fixtures
samples/detections/                      Positive and negative normalized rule fixtures
docs/                                    Design notes for future integrations
scripts/                                 Deploy, stop, reset, and validate helpers
vector/vector.yaml                       Receiver, normalization, buffering, tests
docker-compose.yml                       Pinned service topology
```

## Security boundaries

Fusion is a local lab, not an internet-facing deployment. Grafana, HTTP ingestion, syslog, and the Vector health API bind to `127.0.0.1` by default; ClickHouse and the detection engine are reachable only on the private Compose network. HTTP can be explicitly bound with `FUSION_BIND_ADDRESS` and syslog with the separate `FUSION_SYSLOG_BIND_ADDRESS`. The `/sysmon`, `/linux`, and `/security` paths have no TLS or authentication; TCP/UDP syslog is also plaintext and unauthenticated. Never expose 8686 or 5514 directly to the public Internet, never use `0.0.0.0` as a shortcut, and restrict every lab binding with source-scoped firewall rules.

Do not send real credentials or sensitive production telemetry to the included sample environment. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Development

Validate configuration after changes:

```powershell
.\scripts\validate.ps1
```

The validator checks default and explicit lab bindings for HTTP and TCP/UDP syslog, compiles the collector and Suricata shipper configurations, runs all VRL tests, proves v0.2/v0.3/v0.4 upgrade compatibility, checks the live schemas and container health, sends tagged Windows, Linux, Suricata, RFC 3164, RFC 5424, and unknown-valid-syslog fixtures, validates the curated Sigma rules, proves positive/negative matching and deduplication across restart, tests ingestion with the detection service stopped, executes all three dashboards' queries, and confirms Grafana provisioning. Validate the Windows-only source configuration with `agents/windows/test-config.ps1` and the Vector 0.58.0 Windows executable.

The fixture suite is not a substitute for real-sensor acceptance. The completed v0.4 Suricata acceptance is recorded in [docs/suricata-acceptance.md](docs/suricata-acceptance.md). Fusion v0.5.0 completed real acceptance for Windows encoded PowerShell detection (`T1059.001`), Linux failed SSH authentication (`T1110`), a controlled real Suricata network alert using local acceptance SID `9000001`, and detection-engine restart and deduplication. Detailed evidence is recorded in [docs/detection-acceptance.md](docs/detection-acceptance.md). A release still requires the complete local validator and repository CI to pass; do not create a release tag based on fixtures alone.

Contributions are welcome under the MIT license.

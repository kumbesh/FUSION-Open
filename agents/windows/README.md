# Fusion Windows Vector agent

This directory contains the Fusion v0.2 endpoint agent. It uses Vector 0.58.0's native `windows_event_log` source to read new events from `Microsoft-Windows-Sysmon/Operational`, selects Event IDs 1, 3, 7, 11, 13, and 22, and sends each event as JSON to the existing Fusion `/sysmon` receiver. It does not install or configure Sysmon.

## Prerequisites

- 64-bit Windows supported by Vector 0.58.0
- Administrator access for installation and service control
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) installed, configured, and running independently
- The `Microsoft-Windows-Sysmon/Operational` channel enabled and populated
- TCP reachability to the Fusion host's explicitly configured lab interface

Verify Sysmon before installing the agent:

```powershell
Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
  Select-Object LogName, IsEnabled, RecordCount
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 1,3,7,11,13,22
} -MaxEvents 10 | Select-Object TimeCreated, Id, MachineName
```

[Sysmon's event-filtering configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files) determines which events exist. In particular, Event IDs 3 and 7 may be disabled or heavily filtered by a Sysmon policy.

## Install and operate

First follow the **Connect a Windows Endpoint** section in the repository `README.md` to configure the Fusion bind address and narrow Windows Firewall rule. From an elevated PowerShell session on the endpoint:

```powershell
.\install.ps1 -CollectorUrl 'http://<FUSION_HOST_LAB_INTERFACE_IP>:8686/sysmon'
.\status.ps1
```

Lifecycle scripts:

| Action | Command |
| --- | --- |
| Install and configure | `.\install.ps1 -CollectorUrl '<URL>'` |
| Change collector URL | `.\configure.ps1 -CollectorUrl '<URL>'` |
| Start | `.\start.ps1` |
| Stop | `.\stop.ps1` |
| Check status and recent logs | `.\status.ps1` |
| Uninstall, preserve buffered data | `.\uninstall.ps1` |
| Uninstall and delete agent data | `.\uninstall.ps1 -PurgeData` |

If local execution policy blocks repository scripts, use a process-scoped exception in the same elevated shell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

The installer retrieves the pinned official Vector archive over HTTPS and verifies SHA-256 `72bbedf4772302f7f67e7db2120fe5b42e39ae65873c895876fc2038050c10c5` before installing it. The service runs as the account selected by Vector's native service installer and the agent data ACL permits only SYSTEM and Administrators.

## Behavior and troubleshooting

- `read_existing_events: false` avoids an unexpected historical-event flood. Vector checkpoints new progress under `C:\ProgramData\Fusion\Vector\data`.
- A disk buffer retains queued events during a temporary collector outage.
- `include_xml: true` keeps the rendered Windows XML in the event. Fusion's collector places the entire received object in ClickHouse `raw_json`.
- Local Vector internal logs are written to daily files under `C:\ProgramData\Fusion\Vector\logs`.
- The HTTP sink health check is disabled because `/sysmon` is POST-only. Use `Test-NetConnection <host> -Port 8686`, `status.ps1`, and the ClickHouse query in the main README to validate the path.
- An HTTP 405 from a browser is expected because browsing sends GET; ingestion accepts only POST.

TCP 8686 has no TLS or authentication in v0.2. Use it only on an isolated lab network with a firewall rule restricted to the endpoint VM or lab subnet.

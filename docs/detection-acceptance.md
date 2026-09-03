# Fusion v0.5 real detection acceptance

Status: **pending real Windows, Linux, and Suricata detection evidence**.

The automated fixture suite proves rule parsing, compilation, safe field handling, deterministic identities, deduplication, checkpoint/restart behavior, cross-source matching, dashboard SQL, and ingestion independence. It does not satisfy this real-lab gate.

## Evidence to record

For every test, record the UTC time, lab host, source event UID, detection ID, rule ID, severity, relevant normalized fields, MITRE metadata, and the ClickHouse/Grafana query used to verify it. Do not copy secrets or unrelated raw telemetry into this file.

## Windows

From the connected Windows lab endpoint, run a harmless encoded command in an elevated or normal PowerShell session as appropriate for the lab:

```powershell
$command = "Write-Output 'FUSION-V05-WINDOWS-ACCEPTANCE'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell.exe -NoProfile -EncodedCommand $encoded
```

Confirm a real Sysmon Event ID 1 reaches `fusion.sysmon_events`, then verify `fusion-windows-encoded-powershell` creates one `high` detection containing the real host, process path, command line, source event UID, focused evidence, and MITRE `T1059.001`/PowerShell metadata.

## Linux

Choose one controlled behavior supported by the active audit configuration. The preferred test is opening a disposable sudo shell and exiting immediately:

```sh
sudo /bin/bash -c 'printf "%s\n" FUSION-V05-LINUX-ACCEPTANCE'
```

Confirm the real auditd/journald event is normalized with the expected host, user, action, process/command, and source event UID. Verify the intended Linux rule creates exactly one detection with focused evidence. If the installed audit policy does not emit the fields required by `fusion-linux-sudo-shell`, use the documented authentication-failure test instead and record the reason.

## Suricata

Use the existing isolated Suricata acceptance sensor and its controlled local test signature. Generate only the harmless lab traffic already approved for that sensor. Confirm the EVE alert reaches `fusion.sysmon_events`, then verify the appropriate Suricata rule creates a detection containing the real signature, signature ID, source/destination, severity, source event UID, and evidence.

## Restart continuity

After the three real detections exist:

```sh
docker compose restart fusion-detection-engine
docker compose up --detach --wait --wait-timeout 180 fusion-detection-engine
```

Verify the prior detection IDs remain unique and their physical row counts do not increase merely because of lookback replay. Generate one new controlled matching event and confirm a new detection appears. Record checkpoint time/UID before and after from `fusion.detection_checkpoints FINAL`.

## Useful verification query

```sql
SELECT
    detected_at,
    detection_id,
    rule_id,
    severity,
    platform,
    host_name,
    process_path,
    command_line,
    source_ip,
    destination_ip,
    signature,
    signature_id,
    mitre_tactics,
    mitre_techniques,
    mitre_technique_ids,
    source_event_uid,
    evidence_json
FROM fusion.detections FINAL
ORDER BY detected_at DESC
LIMIT 50;
```

Do not change the status above to complete until all four sections have real evidence.

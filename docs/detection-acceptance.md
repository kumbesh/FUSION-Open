# Fusion v0.5 real detection acceptance

Status: **complete — real Windows, Linux, Suricata, and detection-engine restart/deduplication acceptance passed**.

Acceptance was completed on 2026-09-03 UTC. The detections recorded below came from real lab telemetry and had an empty `validation_id`; synthetic fixture results were excluded. The automated fixture suite remains separate evidence for rule parsing, compilation, safe field handling, deterministic identities, deduplication, checkpoint/restart behavior, cross-source matching, dashboard SQL, and ingestion independence.

## Windows — PASS

A real encoded PowerShell command was executed on the connected Windows endpoint and produced a detection successfully.

- Host: `Kumbesh-Desk`
- Rule: `fusion-windows-encoded-powershell`
- Severity: `high`
- MITRE technique: `T1059.001` — PowerShell
- Source event time: `2026-09-03 21:39:55.641 UTC`
- Detection time: `2026-09-03 21:40:03.783 UTC`
- Source event UID: `f3b0053281de5e7aa315b36ea599cb816dbcc0412a5df6069f92f81142640ebd`
- Detection ID: `d5e86af730875056f886cc2ef60674d33e69bca0c30ba1a86eea4478affa0227`
- `source_event_uid`, `detection_id`, and focused evidence were populated.
- Result: **PASS**

The harmless command used for this controlled test followed this pattern:

```powershell
$command = "Write-Output 'FUSION-V05-WINDOWS-ACCEPTANCE'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
powershell.exe -NoProfile -EncodedCommand $encoded
```

## Linux — PASS

A real failed SSH authentication was generated from Windows and received as normalized Linux telemetry.

- Host: `fusion-ubuntu`
- Username: `definitely-not-a-user`
- Source IP: `192.168.186.1`
- Rule: `fusion-linux-authentication-failure`
- Severity: `low`
- MITRE technique: `T1110` — Brute Force
- Source event time: `2026-09-03 22:16:51.002 UTC`
- Detection time: `2026-09-03 22:16:53.235 UTC`
- Source event UID: `a111b9f91258946f4268423a219fa90a908fa74395e2e09ba715434da8e1c825`
- Detection ID: `f87d5ab1fe3081cd20e1cce8d248b47a8a4ce936c7e3208c4c97f80af5719f51`
- Result: **PASS**

The sudo-shell test produced valid normalized Linux telemetry, but the documented SSH authentication-failure fallback was used for real Linux detection acceptance.

## Suricata — PASS

Real ICMP traffic was generated from `192.168.186.129` to `192.168.186.2` on the isolated lab network. Suricata emitted the controlled local alert, and Fusion created the expected network detection.

- Host: `fusion-ubuntu`
- Source IP: `192.168.186.129`
- Destination IP: `192.168.186.2`
- Local acceptance SID: `9000001`
- Signature: `FUSION TEST v0.5 Controlled Acceptance`
- Rule: `fusion-network-controlled-suricata-signature`
- Severity: `medium`
- Source event time: `2026-09-03 22:03:07.184 UTC`
- Detection time: `2026-09-03 22:03:19.299 UTC`
- Source event UID: `d972a65b4541e0df0594ace05b6dd656ca142b2a91e2711baf147ffdce927193`
- Detection ID: `ca596fc1dbb00c8ab2a82392a391cf7fa479f678dc2ab936645c70fdf217fbfa`
- `evidence_json` was populated.
- Result: **PASS**

The temporary rule was added only to the sensor's local rules file and used this private SID and signature:

```text
alert icmp any any -> any any (msg:"FUSION TEST v0.5 Controlled Acceptance"; sid:9000001; rev:1;)
```

The temporary Suricata acceptance rule was removed afterward. No installed community rule was changed.

## Detection-engine restart and deduplication — PASS

The real Linux authentication detection above was used to verify restart continuity:

- Detection service: `fusion-detection-engine`
- Detection ID checked: `f87d5ab1fe3081cd20e1cce8d248b47a8a4ce936c7e3208c4c97f80af5719f51`
- Count before restart: `1`
- Count after restart: `1`
- No duplicate detection was created during checkpoint resume/lookback replay.
- Result: **PASS**

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

All four mandatory real-lab acceptance sections passed. This record does not include synthetic detections as real acceptance evidence.

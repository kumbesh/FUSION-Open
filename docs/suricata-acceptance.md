# Suricata real-sensor acceptance

Fusion v0.4 real-sensor acceptance was completed on 2026-09-03 UTC using an x86_64 Ubuntu 26.04 VMware VM running Suricata 8.0.3. The sensor, `fusion-ubuntu` (`192.168.186.129`), monitored `ens33` and wrote newline-delimited EVE JSON to `/var/log/suricata/eve.json`. The repository-managed Vector 0.58.0 integration forwarded new EVE records to the lab-restricted Fusion collector at `http://192.168.67.1:8686/security`.

## Evidence

- `suricata.service` and `fusion-suricata-vector.service` were enabled and active.
- Suricata loaded 52,710 rules with zero failures and reported zero kernel capture drops during the initial check.
- Vector validated the generated integration configuration, passed its collector health check, loaded its existing checkpoint, and followed the live EVE file.
- ClickHouse stored real, non-fixture `alert`, `dns`, `http`, `tls`, and `flow` records from `fusion-ubuntu`.
- The accepted sample contained 20 DNS records, one HTTP record, one TLS record, 39 flow records, and two alerts after the corrected shipper started.
- Real DNS v3 records populated `domain`, `query_name`, `query_status`, and `query_results`; `www.example.net` produced `NOERROR` with retained A answers.
- The temporary authorized lab rule `sid:1000001` produced two `FUSION LAB ICMP TEST` alerts with the correct source and destination IPs, ICMP protocol, normalized severity/outcome, signature, and signature ID. The rule was removed after acceptance and Suricata was restarted successfully.
- `raw_json` retained the complete wrapped EVE object, `/var/log/suricata/eve.json` source path, checkpoint offset metadata, and the collector transport peer separately from EVE `source_ip` and `destination_ip`.
- Grafana reported the ClickHouse data source healthy. The provisioned `Fusion Security Sources` alert and DNS queries returned the real accepted records.
- Existing real Windows Sysmon and Linux auditd/journald events continued to arrive while Suricata acceptance ran.

## Feedback-loop finding and correction

The first shipper start revealed that a sensor monitoring its own outbound interface can observe Vector's HTTP requests to Fusion, write those requests back to EVE, and recursively forward them. The shipper was stopped immediately. Exactly 824,201 records from the isolated `2026-09-03 14:24:30` through `14:29:59` UTC incident window were deleted after explicit approval.

The integration now requires a literal collector IP and filters EVE records whose destination IP and port match that collector before forwarding. Two Vector integration tests prove that collector feedback is dropped and unrelated Suricata traffic is retained. After restart, Fusion observed zero collector-feedback records while legitimate EVE traffic continued to arrive.

## Automated verification

The complete Windows PowerShell validator passed on 2026-09-04 after the real-sensor corrections. It covered secure HTTP and syslog bindings, all 24 collector VRL tests, both Suricata shipper tests, the live ClickHouse schema, v0.2-to-v0.3 and v0.3-to-v0.4 migration preservation, container health, Windows/Linux/security JSON fixtures, TCP and UDP syslog, raw-event retention, dashboard SQL, the Grafana data source, and both provisioned dashboards.

## Security boundary

This acceptance applies only to the isolated lab. HTTP 8686 has no TLS or authentication, and the source-scoped host firewall remains part of the required deployment. Docker Desktop may expose the HTTP transport peer to Vector as a bridge address; EVE network fields remain separate and preserve the sensor-observed endpoints.

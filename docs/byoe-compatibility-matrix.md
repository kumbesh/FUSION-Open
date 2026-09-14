# BYOE compatibility matrix

BYOE means **Bring Your Own EDR**. FUSION-Open is designed to complement an
existing endpoint-security product, not replace it:

> Keep your EDR. Bring the telemetry. Correlate everything.

This matrix separates a working transport or file format from a validated
vendor integration. A source being accepted by FUSION does not mean that
FUSION installs or manages that source, understands every vendor field,
creates detections from every received event, or can run response actions in
the vendor product.

## Status definitions

| Status | Meaning |
| --- | --- |
| **Validated** | The stated integration scope exists and is backed by repository tests or recorded controlled real-lab acceptance. The row notes whether the evidence is fixture-based or from a real source. |
| **Supported format** | An existing receiver can accept and preserve the stated representation, but there is no dedicated semantic mapper or vendor acceptance evidence. |
| **Experimental** | An implementation exists for evaluation, but its validation or operating contract is incomplete. No external EDR connector is currently assigned this status. |
| **Planned** | Roadmap or design work only. There is no usable connector, delivery-date commitment, or compatibility claim. |
| **Not supported** | FUSION has no current native receiver, parser, connector, or action for the stated capability. |

## Current integrations and formats

| Source or format | Integration method | Status | Expected data | Scope and notes |
| --- | --- | --- | --- | --- |
| Windows Sysmon | Repository-managed Windows Vector agent reads `Microsoft-Windows-Sysmon/Operational` and sends JSON to `POST /sysmon` | **Validated** | Sysmon Event IDs 1, 3, 7, 11, 13, and 22; the collector also retains other directly submitted Sysmon IDs as `sysmon_other` | Vector tests cover native/nested, Winlogbeat/ECS, flat JSON, and Windows-agent shapes. Controlled real-lab evidence includes encoded PowerShell and endpoint/network correlation. Sysmon must already be installed, configured, and managed independently. |
| Linux auditd | Repository-managed Linux Vector agent tails `/var/log/audit/audit.log` and sends JSON to `POST /linux` | **Validated** | `SYSCALL`, `EXECVE`, `USER_CMD`, `USER_LOGIN`, `USER_AUTH`, `USER_ACCT`, `CRED_ACQ`, and `CRED_DISP` records produced by the endpoint's audit policy | Configuration and tests target Ubuntu 24.04; the recorded real endpoint was x86_64 Ubuntu 26.04. Other distributions and architectures remain unaccepted. FUSION does not install, enable, or configure auditd and starts reading at the end of the audit log. |
| Linux systemd-journald | Repository-managed Linux Vector agent reads selected journal sources and sends JSON to `POST /linux` | **Validated** | Selected SSH, sudo, su, systemd, logind, and login activity from the current boot | Fixture tests cover SSH success/failure, sudo, and systemd activity; controlled real-lab evidence includes Linux SSH telemetry and detections. Collection is filtered and starts at installation time, so this is not an unrestricted or historical journal export. |
| Suricata EVE JSON | Repository-managed Linux Vector shipper tails newline-delimited EVE JSON, wraps each event in the generic security envelope, and sends it to `POST /security` | **Validated** | EVE `alert`, `dns`, `http`, `tls`, and `flow` records | Real-sensor acceptance used Suricata 8.0.3 on x86_64 Ubuntu 26.04 and verified ClickHouse, raw evidence, and Grafana. The shipper requires an existing sensor and a literal collector IP so its feedback-loop filter is deterministic. FUSION does not install or manage Suricata. |
| Generic security JSON / webhook push | One JSON object per HTTP request to `POST /security`; source identity is outside a required nested `event` object | **Validated** | Generic security events with source identity plus currently mapped alert/network fields | The envelope and normalizer have repository test coverage, and Suricata exercises the same live endpoint. This is validation of the generic format, not of an arbitrary EDR. The current `/security` normalizer is network/security-event oriented and does not promote vendor endpoint process or user fields to first-class columns; unmapped vendor context remains in `raw_json`. |
| RFC 3164 syslog | Vector syslog receiver on TCP or UDP port 5514 | **Validated** | Standard syslog envelope fields and message text | Unit coverage validates RFC 3164 normalization, and the full validator sends an RFC 3164 fixture over TCP and verifies it in ClickHouse. Vendor-specific message-body fields are not decoded. The RFC 3164-over-UDP pairing is not separately evidenced by the current end-to-end fixture. |
| RFC 5424 syslog | Vector syslog receiver on TCP or UDP port 5514 | **Validated** | Standard syslog envelope fields and message text | Unit coverage validates RFC 5424 normalization, and the full validator sends RFC 5424 fixtures over UDP and verifies them in ClickHouse. Vendor-specific message-body fields are not decoded. The RFC 5424-over-TCP pairing is not separately evidenced by the current end-to-end fixture. |
| CEF carried inside valid RFC 3164/5424 syslog | Existing TCP/UDP syslog receiver | **Supported format** | Opaque CEF message body inside a valid syslog envelope | FUSION can retain the parsed syslog object and message, but the repository has no CEF parser, extension-field mapper, fixture, or acceptance record. Native CEF semantics require preprocessing into the generic JSON contract or future mapping work. Bare CEF without a valid supported syslog envelope is not claimed. |
| LEEF carried inside valid RFC 3164/5424 syslog | Existing TCP/UDP syslog receiver | **Supported format** | Opaque LEEF message body inside a valid syslog envelope | FUSION can retain the parsed syslog object and message, but the repository has no LEEF parser, attribute mapper, fixture, or acceptance record. Native LEEF semantics require preprocessing into the generic JSON contract or future mapping work. Bare LEEF without a valid supported syslog envelope is not claimed. |

The HTTP and syslog paths above are ingestion paths, not endpoint-control
channels. Receiving an event successfully proves only transport, parsing, and
storage at the scope stated in the row.

## Named EDR and future connector status

The named products below are examples of EDR or security products that may
remain in place beside FUSION. Their **Planned** status is a documentation
roadmap designation only. It is not evidence of vendor certification, tested
compatibility, access to a vendor tenant, or a promised release.

| Product or capability | Proposed integration method | Status | Data type expected | Notes |
| --- | --- | --- | --- | --- |
| Wazuh | Future event connector using an appropriate vendor-supported webhook, syslog, or API path, normalized into the FUSION security envelope | **Planned** | Alerts and security events first; agent/asset context only through a separately designed context connector | There is no Wazuh-specific code, directory, mapping, fixture, or acceptance evidence in the current repository. Do not present this as a committed v0.7 delivery. |
| Microsoft Defender | Future vendor API or event connector, with transport selected only after vendor API review | **Planned** | Endpoint alerts/detections first; device posture or inventory as separate future context | No current connector, authentication flow, field mapper, fixture, response action, or acceptance evidence. |
| CrowdStrike Falcon | Future vendor API or event connector, with transport selected only after vendor API review | **Planned** | Endpoint alerts/detections first; sensor or asset context as separate future context | No current connector, authentication flow, field mapper, fixture, response action, or acceptance evidence. |
| SentinelOne | Future vendor API or event connector, with transport selected only after vendor API review | **Planned** | Endpoint alerts/detections first; agent or asset context as separate future context | No current connector, authentication flow, field mapper, fixture, response action, or acceptance evidence. |
| Other vendor-native EDR integrations | No packaged connector; an operator may independently transform a supported vendor output into the generic JSON or RFC syslog path | **Not supported** | Vendor-dependent | Generic transport compatibility must not be relabeled as vendor-native integration. Add a truthful `source_type`, preserve the original event, and validate a reviewed mapping before claiming compatibility. |
| REST API polling connector framework | Future poller forwarding the existing `/security` envelope | **Planned** | Alerts/detections, with cursor and vendor event identifiers; context data only after a separate schema design | The repository contains a design contract, not an implementation. A connector must define pagination, cursor persistence, overlap, deduplication, rate limits, bounded retry, secret handling, TLS verification, observability, and malformed-record behavior. |
| Endpoint isolation, quarantine, remediation, or other vendor response actions | Vendor control APIs | **Not supported** | None | The current BYOE workflow is telemetry-only. FUSION has no automated endpoint isolation or vendor response action. |

## Detection and correlation boundary

Ingestion does not automatically create a detection or an incident. Current
repository-managed detection mappings name `windows_sysmon`, `linux_auditd`,
`linux_journald`, and `suricata_eve`. The current cross-source network rule is
specifically shaped around a Suricata detection, a Windows endpoint detection,
and a time-valid Sysmon Event ID 3 ownership event. The shipped correlation
rules themselves are marked `experimental` even though their controlled
real-lab scenarios passed.

A future EDR event must therefore keep a truthful vendor/source identity and
first be normalized into approved first-class FUSION fields. It also needs an
applicable, reviewed detection rule before detection-driven correlation can use
it. Do not disguise a vendor event as `windows_sysmon` or `suricata_eve` merely
to make an existing rule match. Preserve the complete vendor-native event in
`raw_json` for investigation and future reprocessing.

A realistic future correlation concept is:

```text
normalized EDR detection
        +
Suricata network detection
        +
approved endpoint or authentication context
        |
        v
one FUSION incident
```

That diagram describes potential value, not current compatibility with any
named EDR event shape.

## Beta and security limitations

**FUSION-Open should complement, not replace, existing endpoint protection.**
Keep the existing EDR responsible for prevention, malware blocking, endpoint
isolation, sensor management, and native remediation.

The current deployment has:

- no automated endpoint isolation, quarantine, or vendor response actions;
- no production SLA;
- no high availability, load balancer, broker, or distributed correlation;
- no full enterprise RBAC or multi-tenancy; and
- no vendor certification implied by generic JSON or syslog ingestion.

It is best suited to a lab, evaluation, or controlled pilot. Conservative
planning bands are **5–25 endpoints** for an initial beta and **25–100
endpoints** for an expanded beta. These are rollout recommendations, not tested
capacity, performance guarantees, or an SLA. Expand beyond them only after
measuring the actual event rate, normalization accuracy, buffer behavior,
ClickHouse growth, dashboard query cost, detection backlog, correlation
backlog, CPU, and memory for the intended telemetry mix.

Apply these security and reliability boundaries:

- HTTP port 8686 has no TLS or authentication. TCP/UDP syslog on port 5514 is
  plaintext and unauthenticated. Both bind to localhost by default; if a lab
  interface is enabled, restrict it to the individual source or isolated lab
  subnet. Never bind it broadly or expose it to the public Internet.
- Anyone who can reach an ingestion listener can inject events. Transport peer
  metadata is evidence, not authentication of the sending product or device.
- Generic JSON is limited to 1 MiB per event. Syslog is limited to 64 KiB per
  message, and the TCP receiver is capped at 100 simultaneous connections.
- UDP can lose messages. Disk buffers are bounded and apply backpressure when
  full. Permanent schema failures and exhausted requests have no ClickHouse
  dead-letter output in the current Vector version.
- `raw_json`, audit records, journal messages, command lines, usernames, and
  vendor evidence can contain sensitive data. Do not send real credentials or
  unnecessary production telemetry to the sample environment; define access,
  retention, and deletion controls before a pilot.
- Detection and correlation results are analytical signals, not proof that an
  event is malicious. Review source evidence in the original security product
  before taking action.

## Future connector boundary

Only `integrations/suricata/` exists today. The following is a proposed roadmap
layout, not a description of current files or shipped integrations:

```text
integrations/
  generic-edr/
  wazuh/
  microsoft-defender/
  crowdstrike/
  sentinelone/
```

Future connectors should remain in two explicit classes:

1. **Event connectors** collect alerts or detections through a supported
   webhook, syslog, API, or event stream. They should emit the existing
   `/security` envelope, preserve the complete vendor response, keep transport
   metadata separate from event network fields, and use a small reviewable
   vendor mapper.
2. **Context connectors** collect assets, sensor health, device posture,
   vulnerabilities, and inventory. FUSION v0.6 has no general asset inventory
   or posture schema, so this data must not be presented as currently ingested
   or forced into unrelated event fields.

The context-connector class is a proposed v0.7-era asset/entity direction, not
a v0.7 delivery commitment. Any implementation needs a reviewed schema,
identity and retention model, permissions, tests, and real acceptance before
its compatibility status changes.

## Repository evidence

- [Collector routes, normalizers, and VRL tests](../vector/vector.yaml)
- [Complete ingestion and ClickHouse validator](../scripts/validate.ps1)
- [Windows agent behavior](../agents/windows/README.md)
- [Linux agent behavior](../agents/linux/README.md)
- [Suricata integration behavior](../integrations/suricata/README.md)
- [Suricata real-sensor acceptance](suricata-acceptance.md)
- [Real Windows, Linux, and Suricata detection acceptance](detection-acceptance.md)
- [Controlled v0.6 correlation acceptance](v06-real-acceptance.md)
- [Current detection field and log-source mapping](../detections/mappings/sigma_fields.yml)
- [Future API connector contract](api-connectors.md)
- [Security policy](../SECURITY.md)
- [Explicit v0.6 out-of-scope items](v06-acceptance-plan.md#explicitly-out-of-scope)

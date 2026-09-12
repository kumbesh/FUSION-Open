# Fusion v0.6 Correlation Model

Status: **frozen v0.6 correlation contract**. The YAML below is an architecture specification, not a runtime rule set.

## Design goals

The v0.6 correlation language must be:

- declarative and repository managed;
- limited to normalized Fusion detection/event fields;
- deterministic across restart and replay;
- explicit about grouping, occurrence-time windows, thresholds, and ordering;
- bounded in document size, selectors, stages, groups, windows, and result counts; and
- impossible to use as arbitrary SQL, a script, or a raw-payload query language.

Sigma remains the source of truth for suspicious-event classification. Correlation uses a separate format because sequence, threshold, episode, and cross-source semantics are materially different from the supported Sigma subset. Correlation may relate a detection to approved normalized facts, but it must not become a second detection engine.

## Frozen YAML shape

```yaml
schema: fusion-correlation/v1
id: fusion-correlation-example
version: 1
status: experimental
title: Example correlation
description: Bounded example only.

window: 10m
allowed_lateness: 15m
group_by:
  - host_name

selectors:
  suspicious:
    source: detection
    where:
      - field: severity
        op: in
        value: [medium, high, critical]

correlate:
  type: threshold
  selector: suspicious
  min_count: 2
  distinct_by: rule_id
  min_distinct: 2

incident:
  type: host_suspicious_activity
  title: "Multiple suspicious detections on {host_name}"
  severity: medium
  confidence: 70
  primary:
    host: host_name

mitre:
  tactic_ids: []
  technique_ids: []

false_positives:
  - Approved administrative or security-testing activity.
```

Only placeholders named by `group_by` or the `incident.primary` mapping may be used in `incident.title`. There is no general template language or environment expansion.

## Fail-closed document rules

The future validator should reject, before engine startup:

- anything other than one YAML document with exact schema `fusion-correlation/v1`;
- duplicate mapping keys, YAML tags, aliases, anchors, merge keys, or object construction;
- an unknown top-level or nested key;
- a duplicate/non-ASCII rule ID or an ID that is not a stable lowercase slug;
- a non-positive integer version;
- oversized strings, documents, collections, or nesting;
- unsupported fields, operators, sources, condition types, time units, or title placeholders;
- a rule without a contributing detection selector, an event-backed threshold, a sequence with no detection stage, a join with no detection input, or an incident whose qualifying set contains no detection;
- any attempt to derive severity, MITRE metadata, or a suspicious-rule count from an event selector;
- `sql`, `query`, free-form `condition`, code, regex, glob, arithmetic, or function syntax;
- references to `raw_json`, `evidence_json`, command bodies, or arbitrary JSON paths; and
- values that exceed the bounds below.

Rule parsing uses YAML safe loading followed by a strict schema. The compiler produces a typed in-memory plan. Runtime queries are fixed and parameterized in trusted engine code; rule text is never concatenated into SQL.

## v0.6 supported subset

### Global bounds

| Construct | v0.6 bound |
| --- | --- |
| selectors | 1-8 per rule |
| predicates | 1-16 per selector; implicit AND only |
| `group_by` | 1-4 scalar keys |
| `window` | integer `s`, `m`, or `h`; 1 second through 1 hour for the initial rules |
| `allowed_lateness` | 0 seconds through 24 hours; initial default 15 minutes |
| threshold | 2-1,000 unique inputs |
| sequence stages | 2-4; stage count 1-100 |
| join selectors | 2 required; one optional endpoint-identity context selector |
| join predicates | maximum 4 allowlisted equality/intersection relations |

An implementation may use lower operational defaults, but it must not silently truncate a valid match. A configured query/result cap that is exceeded produces an observable rule/input failure and leaves the input unledgered for investigation and retry.

### Selector sources and fields

Detection selectors may use only:

`rule_id`, `rule_version`, `severity`, `platform`, `vendor`, `product`, `source_type`, `host_name`, `user_name`, `source_ip`, `destination_ip`, `protocol`, and `signature_id`.

Event selectors may use only:

`event_code`, `event_category`, `event_action`, `event_kind`, `platform`, `vendor`, `product`, `source_type`, `host_name`, `user_name`, `user_id`, `service_name`, `outcome`, `source_ip`, `destination_ip`, `protocol`, and `initiated`.

Every event selector must constrain `source_type` and at least one of `event_category`, `event_action`, or `event_code`. This prevents an event rule from becoming an accidental all-telemetry scan.

The eligible correlation-input union contains all logical detections plus only normalized events that match at least one successfully compiled event selector in the active rule scope. Completeness and backlog metrics refer to this filtered union, not every row in `fusion.sysmon_events`. A new `(correlation_rule_version, correlation_scope_fingerprint)` pair receives a bounded enrollment scope so a newly added event selector can enroll matching retained history.

Every rule must contain a detection selector, and every incident must link at least one detection. An event selector can supply only an approved factual sequence stage or an entity/provenance relationship required by a rule. An event never contributes detection count, detection severity, MITRE classification, or distinct suspicious-rule count. If a normalized event itself needs suspicious classification, a reviewed Sigma rule must place that conclusion in `fusion.detections` first.

Allowed predicate operators are:

- `eq` for one typed scalar;
- `in` for a non-empty bounded list of typed scalars; and
- `exists` for a boolean nonblank/non-null test.

No NOT, substring, wildcard, regular expression, numeric expression, or arbitrary Boolean condition is included in v0.6.

### Canonical identity and ownership normalization

Correlation uses canonical values for equality and identity hashes while retaining the original normalized display values in evidence:

| Entity | Frozen canonical behavior |
| --- | --- |
| Stable IDs | Rule IDs, detection IDs, event UIDs, and persisted anchor IDs remain exact and case-sensitive. Empty or whitespace-only IDs are invalid and are never synthesized or hashed. |
| Windows `DOMAIN\user` | Unicode NFC, trim outer whitespace, split into nonblank down-level realm/account components, and case-fold both. `DOMAIN\Alice` equals `domain\alice`. |
| Windows `user@domain` | Unicode NFC, trim, split at the final `@` into nonblank UPN account/realm components, and case-fold both. `Alice@EXAMPLE.COM` equals `alice@example.com`. |
| Principal namespaces | Down-level `DOMAIN\alice`, UPN `alice@domain`, and bare `alice` remain different canonical principals. v0.6 has no authoritative realm/UPN alias map and does not infer equivalence. |
| Linux user | Unicode NFC and trim, but preserve case because the platform identity is case-sensitive. Windows principals are case-folded; unknown platforms use the safer case-sensitive behavior. |
| Hostname | Unicode NFC, trim, ASCII case-fold, and remove one terminal DNS dot. `Host.Example.COM.` equals `host.example.com`. Short `host`, FQDN `host.example.com`, and other aliases remain distinct without a trusted time-bounded alias fact. |
| IP address | Parse as a typed address; emit canonical compressed lowercase IPv6 or dotted IPv4. Collapse IPv4-mapped IPv6 such as `::ffff:192.0.2.4` to `192.0.2.4`. Invalid, unspecified, loopback, multicast, and zone-scoped/link-local addresses cannot prove a cross-host join. RFC1918 addresses remain valid in the isolated lab. |
| Missing value | A null, empty, or whitespace-only required group component makes that input ineligible for the match, records a visible evaluation reason/counter, and never creates an empty global group. |

Canonical user grouping includes `platform` and the typed full principal representation. Canonical host grouping uses the complete normalized hostname, not an inferred short-name suffix. A future reviewed identity mapping may add aliases, but its bytes and validity interval must enter the correlation semantic fingerprint.

Host/IP ownership is an immutable occurrence-time fact, not a timeless `host -> current IP` cache. The initial fact is `(canonical_host, canonical_local_ip, evidence_event_uid, occurred_at)` from a direction-safe approved endpoint event. A host may have multiple simultaneous ownership facts; each remains separate, and a later fact never overwrites an earlier one. An ownership fact can join only when it, the endpoint detection, and the Suricata detection all satisfy the same inclusive rule window. It cannot be reused by a later episode outside that window. If more than one owned IP intersects the same qualifying input set, the canonical lexical-lowest IP becomes `shared_ip` and the full sorted intersection is retained in bounded evidence.

`shared_ip` is a compiler-owned derived group value available only to this validated ownership join. Simple hostname/IP string equality, a stale fact, an IP later observed on another host, NAT assumptions, or whichever address field happens to be populated never proves ownership.

## Condition types

### Threshold

A threshold references exactly one `source: detection` selector. It counts unique tagged detection identities in an inclusive occurrence-time window and may require a distinct scalar field. Event-backed thresholds are rejected because they would classify normalized events as suspicious outside the detection layer.

```yaml
correlate:
  type: threshold
  selector: suspicious
  min_count: 2
  distinct_by: rule_id
  min_distinct: 2
```

Physical replay rows do not increase either count.

### Sequence

A sequence contains two to four ordered stages. Every stage references a selector and has a minimum count, and at least one stage must use detections. An event stage may assert only an approved non-alert fact such as authentication success. All contributing input identities are distinct. Inputs within one stage may share a millisecond, but every input in stage N must occur strictly before every input in stage N+1; equal-millisecond records across stages do not prove order. The complete first-to-last span is at most the inclusive `window`.

```yaml
correlate:
  type: sequence
  stages:
    - selector: failure
      min_count: 5
    - selector: success
      min_count: 1
```

There are no optional stages, branching expressions, or negative/absence stages in v0.6.

### Join

A join must include at least one detection selector and requires at least one unique input from every named `require` selector in any visibility order. An event selector, when present, is context/provenance only and cannot make an event-only join qualify. The maximum minus minimum occurrence time is at most the inclusive `window`.

For v0.6, relations are limited to:

- scalar `equals` over allowlisted fields; and
- canonical IP-set `intersects` over explicitly listed source/destination fields.

One optional event selector is supported by the language for endpoint host-to-local-IP ownership. It is required by the initial Suricata/endpoint rule because the current detection schema has no trustworthy generic `host_ip`, and fields such as Linux authentication `source_ip` identify the remote client rather than the endpoint. Removing that context selector requires a separate reviewed design with a first-class provenance-safe, time-bounded endpoint ownership field.

```yaml
correlate:
  type: join
  require: [network_alert, endpoint_detection, endpoint_identity]
  relations:
    - left: endpoint_detection.host_name
      op: equals
      right: endpoint_identity.host_name
    - left: network_alert.ip_set
      op: intersects
      right: endpoint_identity.local_ip_set
```

`ip_set` and `local_ip_set` are compiler-owned typed projections, not user code. `local_ip_set` is populated only for source types whose direction/local-address semantics are explicitly mapped—for the initial Windows acceptance, an initiated Sysmon network event supplies `source_ip` as the local address. That event is a point-in-time ownership fact and participates in the same occurrence-window test as both detections. The engine must not infer hostname-to-IP ownership from raw JSON, NAT assumptions, current interface state, or whichever IP field happens to be populated.

## Frozen time and episode semantics

`occurred_at` is the sole authoritative correlation clock. It is detection `source_event_time` or event `event_time`, normalized to UTC millisecond precision. Threshold membership, sequence order, join span, canonical-set selection, anchor time, and episode boundaries use only this value. Missing or invalid occurrence time is never replaced with ingestion time; it produces an observable `invalid_input` evaluation action.

`observed_at` is the stable persisted ingestion/visibility clock—detection `detected_at` or event `ingested_at`. After physical rows are collapsed by logical ID, its canonical value is the minimum persisted visibility time; replay with a later visibility timestamp never refreshes lateness. Conflicting immutable occurrence or entity values for one logical ID fail visibly instead of being chosen by merge order. `observed_at` is used only to enroll retained inputs, rotate recovery scans, calculate backlog/latency, and decide whether occurrence-valid evidence arrived within `allowed_lateness`. Changing observation or processing order never changes membership, order, an anchor, or an episode boundary.

Rule boundaries are frozen as follows:

- Threshold and join qualification is inclusive: `max(occurred_at) - min(occurred_at) <= window`. Exactly `window` matches; `window + 1 ms` does not.
- Sequence stages obey the strict cross-stage order above, while the overall first-to-last span is inclusive at exactly `window`.
- Physical duplicates are collapsed by tagged input identity before selection. Valid minimum-cardinality qualifying sets are serialized from members ordered by `(occurred_at, input_kind, input_id)`; the lexically lowest serialized set is canonical for the currently visible durable input set.
- The threshold anchor is the latest member of its canonical `min_count`/`min_distinct` set. The sequence anchor is the latest member of its terminal stage. The join anchor is the latest member of its canonical minimum set satisfying all required selectors and relations.
- The anchor must have a nonblank stable input ID. It is written to episode state before the completing input is ledgered and never changes after persistence, even if an earlier late input later becomes visible.
- The immutable episode interval is one rule window wide: `episode_window_start = min(occurred_at)` of the canonical qualifying set and `episode_window_end = episode_window_start + window`. Both ends are inclusive. New related evidence may update the episode only inside that interval; unlike a sliding session, an update never moves either end.
- Before closure, occurrence-valid evidence is late-eligible only when `observed_at <= episode_window_end + allowed_lateness`. Closure replaces this with the immutable hard cap `closed_at + allowed_lateness`; closed enrichment cannot extend it.
- A related input at `episode_window_end` may update the episode. An input at `episode_window_end + 1 ms` cannot; it enters new partial state and can create a new deterministic episode only after independently qualifying with unowned inputs.
- Inputs already owned by a qualified rule/group episode cannot satisfy a second incident for that same rule/group. An input whose occurrence belongs to an existing episode but whose observation is after its lateness deadline is accounted with `evaluation_action: no_match` and `lateness_status: late_outside_boundary`; it neither mutates the old incident nor clones that occurrence episode.
- Closure and an observation-deadline breach never move or truncate the occurrence interval. An unowned input whose occurrence is still inside that old interval cannot enrich after the applicable deadline and cannot seed a replacement incident. Only unowned occurrence strictly outside the old interval enters a new partial episode and may create a new deterministic incident after independently qualifying; old owned evidence is never reused.
- If one previously unowned late input could attach to two open episode intervals, v0.6 does not merge or rename incidents. It selects the episode with the nearest anchor time, then lexical `incident_id`, and records a collision metric.

Partial episode state may be retained until `episode_window_end + allowed_lateness` for recovery scheduling. That ingestion-time eligibility rule never changes occurrence membership or boundaries. A newly visible input queries durable neighbors on both sides of its occurrence time, and a previously ledgered neighbor may remain context for its already-owned episode; ledgered means evaluated as a candidate, not deleted from evidence.

## Rule scope, replay, and deduplication

Each rule receives a semantic fingerprint over the schema/compiler version, canonical compiled plan, entity mappings, incident scoring inputs, and MITRE metadata. The positive integer human rule `version`, descriptive prose, file path, and full file hash are not fingerprint bytes: version is an explicit adjacent scope key, while path/hash remain audit metadata. CI still requires a human version bump for semantic changes, and an accidental unversioned semantic edit also changes the fingerprint. Version and fingerprint are included in evaluation scope and incident identity.

The evaluation identity is:

```text
(engine_id, correlation_rule_id, correlation_rule_version,
 correlation_scope_fingerprint, input_kind, input_id)
```

The per-rule ledger is the completeness authority. Cursors and checkpoints are scheduling/diagnostic state only. For a match or update, the normative order is: evaluate; derive the deterministic incident identity and intended membership; write/update the incident; write evidence links; write required rule and episode state; read back and confirm all expected identities/state hashes; write the evaluation ledger; then update the scheduling cursor and cycle telemetry. A no-match/partial branch omits nonexistent incident/link effects but confirms any required state before its ledger row. Replays recompute the same logical effects rather than incrementing counts, so a failure at any intermediate step converges to one incident and duplicate input rows cannot amplify membership.

A new `(correlation_rule_version, correlation_scope_fingerprint)` pair gets a new bounded evaluation scope, including a version-only bump whose fingerprint bytes are unchanged. Old incidents remain attributed to their original pair and are not rewritten. Scope pair A→B→A restores A's persisted floor, rule, episode, and schedule state.

## Initial correlation rules

These are design examples. They are not files to load into the current runtime.

### A. SSH failures followed by successful login

```yaml
schema: fusion-correlation/v1
id: fusion-correlation-ssh-bruteforce-success
version: 1
status: experimental
title: SSH brute force followed by successful login
description: Five failed SSH detections followed by a matching successful SSH event.
window: 5m
allowed_lateness: 15m
group_by: [host_name, user_name, source_ip]
selectors:
  failure:
    source: detection
    where:
      - {field: rule_id, op: eq, value: fusion-linux-authentication-failure}
  success:
    source: event
    where:
      - {field: source_type, op: eq, value: linux_journald}
      - {field: event_category, op: eq, value: authentication}
      - {field: event_action, op: eq, value: ssh_login}
      - {field: service_name, op: eq, value: ssh}
      - {field: outcome, op: eq, value: success}
correlate:
  type: sequence
  stages:
    - {selector: failure, min_count: 5}
    - {selector: success, min_count: 1}
incident:
  type: ssh_bruteforce_then_success
  title: "SSH failures followed by success on {host_name}"
  severity: high
  confidence: 90
  primary: {host: host_name, user: user_name, source_ip: source_ip}
mitre:
  tactic_ids: [TA0006]
  technique_ids: [T1110]
false_positives:
  - User typing errors, expired credentials, scanners, shared NAT, or approved tests.
```

- **Sources:** five unique logical failure detections plus one normalized success event.
- **Grouping/window:** exact nonblank canonical host, platform-aware full principal, and remote canonical IP; all failure-stage inputs strictly precede the success stage; total span at most the inclusive five-minute boundary.
- **Severity:** high base; child severity can only raise it under the shared incident policy.
- **Identity:** the terminal success `event_uid` is the episode anchor.
- **Dedup/update:** replay adds no link or count. Later matching evidence updates the same incident only inside the immutable episode/lateness bounds. The same five failures cannot manufacture a new incident for every later success; owned inputs are recorded in episode state. Five unowned failures and a later success beyond the prior occurrence boundary can form a new episode.
- **False positives:** exact three-part grouping contains, but does not eliminate, shared-NAT and operational-login noise. Suppression/allowlists are not part of the v0.6 language.
- **Acceptance:** 4 failures plus success = none; 5 failures without success = none; success first = none; 5 failures plus success at exactly 5m = one; success at 5m+1ms = none; different/blank group key = none. A duplicate failure cannot satisfy the threshold. Late success and a late pre-success fifth failure within the fixed lateness boundary each converge to the same incident and anchor.

Real acceptance must use one disposable owned lab account, exactly five deliberate failures, then one correct login. It must not use a nonexistent username for the positive sequence, a wordlist, password guessing, or a public target.

### B. Multiple suspicious detections on one host

```yaml
schema: fusion-correlation/v1
id: fusion-correlation-host-suspicious-activity
version: 1
status: experimental
title: Multiple suspicious detections on one host
description: Two distinct medium-or-higher detection rules on one host.
window: 10m
allowed_lateness: 15m
group_by: [host_name]
selectors:
  suspicious:
    source: detection
    where:
      - {field: severity, op: in, value: [medium, high, critical]}
correlate:
  type: threshold
  selector: suspicious
  min_count: 2
  distinct_by: rule_id
  min_distinct: 2
incident:
  type: host_suspicious_activity
  title: "Multiple suspicious detections on {host_name}"
  severity: medium
  confidence: 70
  primary: {host: host_name}
mitre: {tactic_ids: [], technique_ids: []}
false_positives:
  - Administrative automation, vulnerability scans, red-team activity, or noisy rules.
```

- **Sources:** current logical `fusion.detections` rows.
- **Grouping/window:** nonblank canonical host; two distinct rule IDs in ten minutes.
- **Severity:** the higher of the medium rule base and the child detections, with no hidden arithmetic boost.
- **Identity:** the detection that completes the first canonical two-distinct-rule set is the episode anchor.
- **Dedup/update:** a third distinct qualifying detection inside the immutable episode/lateness bounds updates membership/counts/MITRE arrays without changing the ID. Counts are recomputed from links. Post-boundary unowned detections must independently qualify a new episode.
- **False positives:** requiring two rule IDs prevents repeated output from one noisy rule from qualifying, but authorized multi-tool activity can still match.
- **Acceptance:** two different rule IDs on the same host at 9m59s or exactly 10m = one incident; 10m+1ms, different hosts, low-only inputs, a blank host, or the same rule twice = none. Replay is unchanged.

### C. Suricata and endpoint correlation

```yaml
schema: fusion-correlation/v1
id: fusion-correlation-suricata-endpoint
version: 1
status: experimental
title: Suricata alert corroborated by endpoint activity
description: A network detection and endpoint detection tied by proven endpoint IP context.
window: 10m
allowed_lateness: 15m
group_by: [shared_ip, host_name]
selectors:
  network_alert:
    source: detection
    where:
      - {field: source_type, op: eq, value: suricata_eve}
  endpoint_detection:
    source: detection
    where:
      - {field: platform, op: eq, value: windows}
  endpoint_identity:
    source: event
    where:
      - {field: source_type, op: eq, value: windows_sysmon}
      - {field: event_code, op: eq, value: "3"}
      - {field: initiated, op: eq, value: 1}
correlate:
  type: join
  require: [network_alert, endpoint_detection, endpoint_identity]
  relations:
    - {left: endpoint_detection.host_name, op: equals, right: endpoint_identity.host_name}
    - {left: network_alert.ip_set, op: intersects, right: endpoint_identity.local_ip_set}
incident:
  type: cross_source_network_endpoint
  title: "Network and endpoint activity on {host_name}"
  severity: high
  confidence: 85
  primary: {host: host_name}
mitre: {tactic_ids: [], technique_ids: []}
false_positives:
  - NAT, proxies, shared infrastructure, DHCP changes, scanners, or clock skew.
```

- **Sources:** one Suricata detection, one Windows endpoint detection, and one normalized initiated Sysmon network context event proving host/IP ownership. A future Linux variant requires its own direction-safe local-IP mapping.
- **Grouping/window:** canonical shared IP plus endpoint host; the Suricata detection, endpoint detection, and direction-safe ownership fact must all fall within the same inclusive ten-minute occurrence span; arrival order is irrelevant.
- **Primary IPs:** retain the Suricata source/destination direction when it is unambiguous; do not force the shared entity into `primary_source_ip` when it was actually the destination.
- **Severity:** high rule base; the incident is the higher of that base and its child-detection severity, with no hidden cross-source boost.
- **Identity:** latest member of the canonical minimum qualifying set, with canonical shared IP and full endpoint hostname in the group key; the persisted anchor never changes.
- **Dedup/update:** network-first, endpoint-first, and context-last visibility paths converge to the same logical incident and links. Further evidence updates only inside the immutable episode/lateness bounds; a later IP fact never overwrites ownership used by the incident.
- **False positives:** IP intersection is evidence, not asset identity. Field provenance is stored. Empty/invalid/unspecified/loopback/multicast IPs do not join; private lab IPs do.
- **Acceptance:** controlled Suricata SID `9000001` with signature beginning `FUSION TEST`, a real endpoint detection, and a real initiated endpoint network event proving IP X within ten minutes = one cross-source incident. No ownership fact, stale ownership, ownership by another host, no intersection, wrong host binding, more than ten minutes, two Suricata-only records, or blank/invalid IP = none. IPv4 and its IPv4-mapped IPv6 form join; simultaneous multiple host IPs retain separate ownership facts. The temporary Suricata rule is removed afterward.

If implementation chooses a new first-class provenance-safe endpoint `host_ip` instead, design review may reduce this to two selectors. It must never reinterpret arbitrary existing `source_ip` as local ownership.

### D. Multiple detection rules for one user

```yaml
schema: fusion-correlation/v1
id: fusion-correlation-user-suspicious-activity
version: 1
status: experimental
title: Multiple suspicious detections for one user
description: Two distinct detection rules for one normalized platform principal.
window: 15m
allowed_lateness: 15m
group_by: [platform, user_name]
selectors:
  user_detection:
    source: detection
    where:
      - {field: platform, op: in, value: [windows, linux]}
      - {field: user_name, op: exists, value: true}
correlate:
  type: threshold
  selector: user_detection
  min_count: 2
  distinct_by: rule_id
  min_distinct: 2
incident:
  type: identity_suspicious_activity
  title: "Multiple suspicious detections for {user_name}"
  severity: medium
  confidence: 70
  primary: {user: user_name}
mitre: {tactic_ids: [], technique_ids: []}
false_positives:
  - Shared accounts, local-name collisions, service accounts, or approved administration.
```

- **Sources:** current logical Windows/Linux detections with nonblank users.
- **Grouping/window:** `(platform, typed canonical full principal)` for the inclusive 15-minute window. Cross-host membership within one platform is intentional. Windows principal casing is ignored, Linux casing is preserved, and v0.6 does not infer that down-level, UPN, bare, Windows, and Linux identities are equivalent.
- **Threshold:** two distinct Sigma rule IDs, not two physical detections from one rule.
- **Severity/identity/update:** medium base, child max, deterministic second-distinct-rule anchor, and stable updates from authoritative links.
- **False positives:** usernames are not a global principal ID. Domain/realm syntax is preserved; `DOMAIN\alice`, `alice@domain`, and bare `alice` do not merge without authoritative mapping.
- **Acceptance:** two distinct rules for the same canonical platform/principal within exactly 15m = one; same rule twice, different platform/principal syntax, 15m+1ms, blank user, or Suricata-only input = none. Windows case-only variants match, Linux case-only variants remain distinct, replay does not amplify, and a late second rule inside the fixed boundary converges once.

## Required state behavior

- Candidate inputs are processed per rule scope, not once globally; the same detection may legitimately support different correlation rules.
- Previously ledgered inputs remain queryable context for a newly visible candidate.
- Episode state persists the group, canonical qualifying set, immutable anchor/window bounds, owned input IDs, and incident ID so restart cannot reuse evidence across episodes.
- Identity is guaranteed stable after the canonical match and anchor are persisted. Arrival permutations of the same minimal qualifying set must yield the same ID; arbitrary supersets with competing first matches are not claimed to be globally arrival-history independent, and never mutate a persisted anchor.
- Incident and link counts are recomputed from distinct logical links, never incremented from messages.
- A repeatably failing input stays unledgered and rotates through bounded candidate pages; it cannot starve the rest of a rule's backlog.
- A same-timestamp threshold/join remains deterministic by tagged input ID. A same-timestamp sequence does not claim an order.
- Rule scope pair A→B→A, where each pair is `(correlation_rule_version, correlation_scope_fingerprint)`, restores A's own ledger, enrollment floor, rule, episode, and schedule state.

## Known model limitations

- No negative/absence, rate, cardinality-over-unbounded-dimensions, or graph correlation.
- No cross-rule incident merging.
- No asset inventory, NAT resolution, DHCP history, or universal principal identity.
- No suppression language, calendars, or allowlist subqueries.
- No unlimited backfill; each new semantic scope has a bounded fixed enrollment floor.
- Episode identity is stable after creation, but arbitrary from-empty arrival histories with competing extra matches can create different first episode anchors; v0.6 does not auto-merge them.
- Per-rule ledgers increase storage and anti-join cost linearly with active rule scopes.

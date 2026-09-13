# Fusion v0.6 Incident Model

Status: **frozen v0.6 incident contract**. The schemas below are logical designs, not migrations.

## Definition

A Fusion incident is a durable, versioned conclusion that one repository-managed correlation rule matched a related set containing at least one normalized detection, plus any approved factual context events, for a canonical entity group and correlation episode. Raw normalized events never establish suspiciousness or create an event-only incident.

An incident is not a case-management ticket, proof of compromise, or mutable copy of all source telemetry. It records:

- why the correlation matched;
- the current severity, confidence, and lifecycle state;
- the primary affected entities;
- durable links to the supporting detections/events; and
- a compact, ordered evidence timeline.

One incident is owned by one correlation rule ID and version. Different correlation rules may produce separate incidents from the same detections. v0.6 does not merge incidents across rules.

## Logical incident fields

| Field | Logical type | Meaning |
| --- | --- | --- |
| `incident_id` | String | Deterministic SHA-256 identity for one rule/group episode |
| `incident_title` | String | Rule-defined title rendered with allowlisted entity values |
| `incident_type` | LowCardinality(String) | Stable type such as `ssh_compromise`, `host_compromise`, `cross_source`, or `identity_activity` |
| `status` | LowCardinality(String) | `new`, `acknowledged`, or `closed` |
| `severity` | LowCardinality(String) | Deterministic `low`, `medium`, `high`, or `critical` |
| `severity_rank` | UInt8 | Stable numeric rank 1-4 used for comparisons |
| `confidence` | UInt8 | Rule-declared explainable score from 0 through 100 |
| `created_at` | DateTime64(3, UTC) | First durable creation time |
| `updated_at` | DateTime64(3, UTC) | Time of the latest incident revision |
| `first_seen` | DateTime64(3, UTC) | Earliest linked occurrence time |
| `last_seen` | DateTime64(3, UTC) | Latest linked occurrence time |
| `acknowledged_at` | Nullable(DateTime64(3, UTC)) | First transition to acknowledged |
| `closed_at` | Nullable(DateTime64(3, UTC)) | Transition to terminal closed state |
| `last_transition_id` | String | Idempotency token of the latest applied lifecycle transition |
| `last_transition_from` | LowCardinality(String) | Prior status captured with that transition |
| `last_transition_at` | Nullable(DateTime64(3, UTC)) | Applied time needed to reconstruct a missing audit row |
| `primary_host` | String | Rule-selected primary host, otherwise deterministic first nonblank host |
| `primary_user` | String | Rule-selected primary normalized user |
| `primary_source_ip` | String | Rule-selected canonical source IP |
| `primary_destination_ip` | String | Rule-selected canonical destination IP |
| `input_count` | UInt32 | Distinct linked detection plus event inputs |
| `detection_count` | UInt32 | Distinct linked detections |
| `event_count` | UInt32 | Distinct linked normalized source events |
| `distinct_detection_rule_count` | UInt16 | Distinct child Sigma rule IDs |
| `source_family_count` | UInt8 | Distinct source families contributing evidence |
| `related_detection_ids` | Array(String), derived | Sorted detection IDs aggregated from authoritative links; not stored in the incident table |
| `mitre_tactic_ids` | Array(String) | Sorted unique rule-declared and locally mapped tactic identifiers |
| `mitre_technique_ids` | Array(String) | Sorted unique rule-declared and child technique identifiers |
| `correlation_rule_id` | String | Stable declarative rule ID |
| `correlation_rule_version` | UInt32 | Positive integer human-reviewed semantic version |
| `correlation_scope_fingerprint` | String | Hash of exact compiler/rule/mapping semantics |
| `group_key_json` | String | Canonical, bounded group values used by the rule |
| `group_key_hash` | String | SHA-256 of canonical group-key JSON |
| `episode_anchor_kind` | LowCardinality(String) | `detection` or `event` |
| `episode_anchor_id` | String | Persisted identity of the first canonical qualifying episode anchor |
| `episode_anchor_time` | DateTime64(3, UTC) | Occurrence time of that anchor |
| `episode_window_start` | DateTime64(3, UTC) | Immutable earliest occurrence in the canonical qualifying set |
| `episode_window_end` | DateTime64(3, UTC) | Immutable inclusive bound `episode_window_start + window` |
| `last_evidence_observed_at` | DateTime64(3, UTC) | Latest visibility time of accepted evidence |
| `late_accept_until` | DateTime64(3, UTC) | Immutable current observation-time deadline for bounded retroactive enrichment |
| `late_update_count` | UInt32 | Number of inputs attached retroactively within the allowed grace |
| `revision` | UInt64 | Monotonic single-writer replacement revision |
| `state_hash` | String | Hash of the canonical incident snapshot for idempotent replay checks |
| `revision_source` | LowCardinality(String) | `correlation_input` or `lifecycle_transition` |
| `revision_token` | String | Deterministic evaluation-key hash or lifecycle transition ID used by confirmation-aware serving views |
| `evidence_json` | String | Versioned, compact explanation of the correlation and scoring inputs |

`related_detection_ids` belongs to the incident read model, but the link table is the only membership authority. Storing both a writable array and writable links would create a cross-table consistency problem that ClickHouse cannot transact atomically.

## Deterministic incident identity

The frozen identity is:

```text
SHA-256(
  "fusion-incident-v1" + NUL +
  correlation_rule_id + NUL +
  correlation_rule_version + NUL +
  correlation_scope_fingerprint + NUL +
  canonical_group_key_json + NUL +
  episode_anchor_kind + ":" + episode_anchor_id
)
```

Group values use the platform-aware principal, full-hostname, canonical-IP, missing-value, and time-bounded ownership rules frozen in [v06-correlation-model.md](v06-correlation-model.md). Canonical JSON uses schema-ordered keys and explicit typed values; display strings never enter the identity preimage.

The fingerprint is computed from the schema/compiler version, canonical compiled semantics, entity mappings, incident scoring inputs, and MITRE metadata. The positive integer human rule version is a separate identity component and is not fingerprint input. CI still requires a version bump for a semantic change; the fingerprint independently prevents an accidental unversioned change from aliasing an old incident.

Before qualification, partial state uses a deterministic `episode_state_id` derived from the rule scope, canonical group, and earliest unowned tagged input; it has no `incident_id` or incident anchor. An episode anchor is created exactly once, when that partial rule/group episode first qualifies. The engine collapses physical duplicates to unique `(input_kind, input_id)` values, orders them by `(occurred_at, input_kind, input_id)`, enumerates valid minimum-cardinality qualifying sets, serializes each set in that order, and chooses the lexically lowest serialization visible in durable input at that evaluation. It then chooses the anchor as:

- sequence: the latest input in the terminal stage of that set;
- threshold: the latest ordered input in the canonical minimum-size qualifying set;
- join: the latest ordered input in the canonical minimum set satisfying every required side.

The anchor ID must be nonblank. The anchor, canonical qualifying set, and occurrence interval are persisted before the completing input is marked evaluated and never change afterward. Observation/processing order, a late earlier input, or later evidence cannot rename or merge an existing incident. With additional competing inputs, the first qualifying set can differ across from-empty visibility histories; v0.6 guarantees stable identity after episode creation, while acceptance permutations of the same minimal set must converge to the same ID.

The immutable inclusive occurrence interval is one rule window wide: `episode_window_start` is the earliest occurrence time in the canonical qualifying set and `episode_window_end = episode_window_start + window`. For a sequence, only inputs satisfying the declared stage order can qualify the incident; other in-range records are supporting context only when explicitly selected. Inputs owned by one qualified rule/group episode cannot seed another. Unowned activity beyond `episode_window_end` creates new partial state and a new deterministic incident only after independently qualifying.

## Frozen persistence and replay order

For every incident creation, update, or enrichment, the required order is:

```text
evaluate
  -> derive deterministic incident identity and intended membership
  -> write/update incident
  -> write evidence links
  -> write correlation rule and episode state
  -> read back and confirm every expected write
  -> mark input evaluated in the correlation ledger
  -> update scheduling cursor and diagnostic state
```

The incident snapshot is calculated from the canonical intended membership in memory, even though links are the durable membership authority and are written next. The incident revision, every newly introduced link, and each candidate-mutated rule/episode state revision carry the same deterministic evaluation `revision_token`. Confirmation requires the expected incident `state_hash`/revision, exact logical link IDs/tokens, and expected rule/episode state hashes/tokens to be visible. Any missing or mismatched effect leaves the input unledgered. A no-match or partial sequence writes and confirms only the required rule/episode state before ledgering; it never creates a dummy incident or link.

Replay after any crash recomputes the same identities. An unchanged incident `state_hash` is a no-op, link identities deduplicate by tagged input, and episode membership is set-derived rather than incremented. A crash after the ledger but before schedule-state update is recovered by the ledger anti-join. Thus every intermediate failure converges to one logical incident, exact logical evidence membership, and one evaluation-ledger identity.

ClickHouse may expose partial raw-table writes during this sequence. Incident and semantic-state tables preserve every logical revision so a provisional higher revision cannot be merged over the last confirmed one. Committed-state views admit correlation-created incident revisions, newly introduced links, and candidate-mutated semantic-state revisions only when their shared token is backed by the exact evaluation-ledger row; lifecycle revisions require the transition-audit token. The one exception is immutable rule-scope bootstrap state, which requires the dedicated durable bootstrap-confirmation row defined below and cannot contain per-input completion or episode membership. An already confirmed link retains its original confirmation token and is never hidden by an unconfirmed replay. Provisional episode state cannot suppress its unledgered candidate. Grafana therefore never treats an unconfirmed incident revision or link as current.

## Incident lifecycle

### States and transitions

```text
new ---------> acknowledged ---------> closed
 |                                      ^
 +--------------------------------------+
```

Allowed lifecycle transitions are:

- `new -> acknowledged`
- `new -> closed`
- `acknowledged -> closed`

Repeated requests for the current state are idempotent. `acknowledged -> new`, `closed -> new`, and `closed -> acknowledged` are rejected. v0.6 has no reopen transition.

Lifecycle fields follow these rules:

- `created_at` is immutable.
- `acknowledged_at` is set once on the first acknowledgement and retained after closure.
- `closed_at` is set once on closure.
- `updated_at` and `revision` change for lifecycle transitions and correlation evidence updates.
- `first_seen` and `last_seen` describe evidence occurrence time, not processing time.

### New evidence and closed incidents

- A `new` or `acknowledged` incident is updated in place only when new related evidence belongs to the same rule/group, has occurrence time inside the immutable inclusive episode interval, and is observed no later than `late_accept_until`.
- `closed` is terminal and is never reopened automatically.
- A closed incident may receive evidence enrichment only when the input matches an approved selector, its occurrence is inside the immutable episode interval and no later than `closed_at`, and its observation time is at or before the fixed `closed_at + allowed_lateness` cap. Status, lifecycle timestamps, and rule-declared confidence do not change; links, counts, evidence, and severity may receive an auditable revision.
- Closure never moves or truncates the immutable occurrence interval. An input after `closed_at`, or observed after the closed deadline, cannot attach; when its occurrence is still inside the old interval it is accounted as `no_match`/`late_outside_boundary` and cannot clone that episode.
- Only unowned activity whose occurrence is strictly outside the old episode interval enters a new partial episode. It creates a new deterministic incident only after independently satisfying the rule without reusing evidence owned by the closed episode.

In this contract, “activity after the closed deadline” means newly occurring activity, not merely late ingestion of old activity. It follows the new-episode path above; late delivery cannot duplicate an old occurrence episode.

These rules keep closure meaningful while preserving bounded retroactive evidence handling.

### Episode and lateness clocks

- `occurred_at` alone controls threshold membership, sequence order, join span, anchor selection, and episode boundaries. Detection `source_event_time` and event `event_time` are authoritative; there is no ingestion-time fallback.
- `episode_window_start` is the earliest canonical qualifying-set occurrence, and the inclusive `episode_window_end` is exactly start plus `window`. Both are immutable.
- `observed_at` is stable source visibility time—detection `detected_at` or event `ingested_at`—and is used only for enrollment/recovery, backlog/SLOs, and lateness eligibility.
- While status is `new` or `acknowledged`, `late_accept_until = episode_window_end + allowed_lateness`. It is fixed and accepting evidence does not slide it.
- On transition to `closed`, `late_accept_until` is replaced with the hard, immutable cap `closed_at + allowed_lateness`. Evidence accepted before that cap does not extend it.
- Both occurrence boundaries and the observation deadline are inclusive. One millisecond beyond either applicable bound cannot update that episode.
- A partial, not-yet-qualified episode may remain recovery-eligible only through its occurrence window plus `allowed_lateness`; this retention decision never changes occurrence membership or boundaries.
- The evaluation ledger stores separate `evaluation_action` and `lateness_status`. For example, an old-interval input observed outside grace is `no_match` plus `late_outside_boundary`, while an independently qualifying episode built from unowned occurrence outside the old interval is `created` plus its applicable lateness status.

These rules make the wall-clock grace testable and prevent “quiet” from being an undefined operator judgment.

### Lifecycle mutation ownership

Grafana remains read-only and no public lifecycle API is added. The frozen v0.6 control is a restricted local admin command invoked with `docker compose exec` that talks to the running correlation engine over a container-private Unix socket. The single engine process serializes correlation and lifecycle mutations, validates the allowed transition, writes a new incident revision, then records an immutable transition audit row. Docker-host access is the administrative boundary for this lab design.

The command accepts only incident ID, target status, and an idempotency token. It does not add comments, assignment, ticketing, or workflow behavior. The incident revision persists `last_transition_id`, prior status, target `status`, and applied time before the audit write. A retry with the same token can therefore reconstruct a missing audit row exactly without guessing whether the prior state was `new` or `acknowledged`; otherwise it is a no-op. Whether this local socket/command is accepted must be frozen before implementation; direct ad hoc SQL status updates are not supported.

## Deterministic severity and confidence

Severity ranks are fixed:

| Severity | Rank |
| --- | ---: |
| `low` | 1 |
| `medium` | 2 |
| `high` | 3 |
| `critical` | 4 |

The incident severity is simply the higher of the correlation rule's declared severity and the highest linked child-detection severity. Every incident has at least one detection; normalized context events never raise severity, add MITRE classification, or contribute a suspicious-rule count, and event-only incident rules are rejected. Missing/unknown child severities never raise the result. Cross-source importance is expressed explicitly by the correlation rule's base severity rather than a hidden arithmetic boost. The result is monotonic while links are only added, capped at `critical`, and its inputs are recorded in `evidence_json`.

Each rule declares a fixed `confidence` from 0 through 100. The engine copies that value to the incident; it does not infer a probability or add hidden bonuses. Authors justify the score in rule review, and the four initial examples fixture-test the exact value. The dashboard labels it **correlation confidence**, not probability of compromise.

`mitre_technique_ids` is the sorted unique union of rule-declared IDs and linked child-detection IDs. `mitre_tactic_ids` comes from rule declarations plus a versioned repository-local technique-to-tactic-ID mapping. The current human-readable `mitre_tactics` names are not reverse-parsed into ATT&CK IDs, and there is no runtime network lookup. The mapping bytes are part of the correlation semantic fingerprint.

## Incident evidence JSON

`evidence_json` must use a versioned object containing only bounded correlation rationale:

- evidence schema version;
- rule ID/version/fingerprint;
- normalized group values;
- matched condition type, threshold/stages, and window;
- canonical trigger and supporting input IDs;
- counts and distinct-count values;
- severity and confidence calculation inputs;
- whether the update was late and the measured lateness; and
- any safe false-positive notes supplied by the rule.

It must not contain raw event JSON, credentials, full command lines, arbitrary source payloads, or unbounded arrays. Source investigation remains available through authorized joins to retained source data.

## Logical ClickHouse table contract

The following are table designs, not executable DDL.

### `fusion.incidents`

- **Columns:** all persisted incident fields above except derived `related_detection_ids`.
- **Engine:** `ReplacingMergeTree(updated_at)` with revision preserved in the sorting key.
- **ORDER BY:** `(incident_id, revision)`.
- **Partitioning:** `toYYYYMM(created_at)`.
- **Idempotency:** deterministic `incident_id`; single-writer monotonic `revision`; an unchanged `state_hash` is a replay no-op and produces no new logical revision. Replays of one revision collapse by `(incident_id, revision)` without removing other revisions.
- **Update model:** append a revision-preserving full row only for changed canonical state. Serving paths filter confirmation-backed tokens and then select the highest remaining revision. No TTL or merge may discard the last confirmed predecessor while a provisional revision exists.
- **Retention:** no v0.6 TTL until incident, link, detection, and source retention are frozen together. Open incidents must never disappear because a child TTL expired.

Useful secondary indexes may target status/severity, group hash, primary host/user, and correlation rule, but must be justified by measured dashboard queries.

### `fusion.incident_detection_links`

- **Columns:** `incident_id`, `detection_id`, deterministic `link_id`, deterministic `introduction_revision_token`, `relationship` (`trigger`, `supporting`, or `context`), `occurred_at`, canonical earliest source `observed_at`, `linked_at`, correlation rule ID/version/fingerprint, and a minimal immutable snapshot: source type, Sigma rule ID/name, severity, host, user, source/destination IP, MITRE technique IDs, and bounded summary.
- **Engine:** `ReplacingMergeTree(linked_at)` or an equivalent immutable deduplicating design.
- **ORDER BY:** `(incident_id, detection_id)`; occurrence time remains a stored immutable timeline column.
- **Partitioning:** `toYYYYMM(occurred_at)`.
- **Idempotency:** `link_id = SHA-256(incident_id + NUL + detection_id)`; the occurrence timestamp is immutable for one detection. The introduction token identifies the exact evaluation revision that first proposes the link.
- **Update model:** links are insert-only logically. Serving includes a link only when its introduction token has an exact ledger row. Replay of a provisional link uses the same token; an already confirmed link is never replaced by a later unconfirmed token.
- **Retention:** no independent TTL in v0.6. A future purge must remove incident and links as one reviewed operation.

### `fusion.incident_event_links`

- **Columns:** the same introduction token, relationship, and snapshot shape, including canonical earliest source `observed_at`, using `event_uid` and normalized event category/action/outcome/service in place of Sigma metadata.
- **Engine:** same as detection links.
- **ORDER BY:** `(incident_id, event_uid)`; occurrence time remains a stored immutable timeline column.
- **Partitioning:** `toYYYYMM(occurred_at)`.
- **Idempotency:** `link_id = SHA-256(incident_id + NUL + event_uid)` with an explicit `event` namespace in the preimage.
- **Retention/update/serving:** same confirmation-backed contract as detection links.

This extra table is required because the SSH success is a normalized event rather than a v0.5 detection. Hiding such evidence only inside JSON would make membership non-queryable and fragile.

### `fusion.correlation_evaluated_inputs`

- **Columns:** `engine_id`, `correlation_rule_id`, positive integer `correlation_rule_version`, `correlation_scope_fingerprint`, `input_kind`, `input_id`, authoritative occurrence time, canonical earliest observation time, evaluation time, `evaluation_action` (`no_match`, `created`, `updated`, `enriched_closed`, or `invalid_input`), `lateness_status` (`on_time`, `late_within_boundary`, `late_outside_boundary`, or `not_applicable`), resulting incident ID when any, deterministic evaluation/revision token, safe reason code, source type, host, and validation ID. Transiently failed inputs are not ledgered and remain visible for retry.
- **Engine:** `ReplacingMergeTree(evaluated_at)`.
- **ORDER BY:** `(engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, input_kind, input_id)`.
- **Partitioning:** `toYYYYMM(observed_at)`.
- **Idempotency:** the ORDER BY identity is the completeness key. A row is written only after all required effects have been read back and confirmed.
- **Update model:** logically insert-once; a replay may replace with the same final result.
- **Retention:** no independent TTL while an eligible input can still participate in retained correlation history. Old rule scopes require observable capacity management.

### `fusion.correlation_rule_state`

- **Columns:** engine/rule/positive integer version/fingerprint, fixed evaluation floor, compiler/normalization contract versions, deterministic `revision_token`, rule-state hash, activation time, update time, and revision. It contains no candidate cursor.
- **Engine:** `ReplacingMergeTree(updated_at)` with revision preserved in the sorting key.
- **ORDER BY:** `(engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, revision)`.
- **Partitioning:** none; this is a small state table.
- **Idempotency/update:** candidate-mutated revisions use the same evaluation revision token as the incident/links and become committed only when that ledger token exists. Initial bootstrap state uses a deterministic `scope_bootstrap` token, is read-back verified, and becomes committed only after its exact row appears in `fusion.correlation_scope_bootstrap_confirmations`; candidate polling cannot start earlier. Bootstrap state cannot assert per-input completeness.
- **Authority:** semantic rule-scope and fixed enrollment state only. It is confirmed before the evaluation ledger but never proves per-input completeness.
- **Retention:** retain while a scope ledger or incident references the fingerprint; stale scope cleanup is an explicit future administration task.

### `fusion.correlation_episode_state`

- **Columns:** engine/rule/positive integer version/fingerprint, canonical group JSON/hash, deterministic episode state ID, deterministic evaluation `revision_token`, persisted canonical qualifying set, immutable anchor kind/ID/time, immutable inclusive window start/end, active incident ID when qualified, sorted bounded owned detection/event IDs, update/late-expiry times, collision count, state hash, update time, and revision.
- **Engine:** `ReplacingMergeTree(updated_at)` with revision preserved in the sorting key.
- **ORDER BY:** `(engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, group_key_hash, episode_state_id, revision)`.
- **Partitioning:** none for the initial bounded lab state.
- **Idempotency/update:** full member sets are sorted/unique and replacement rows use a deterministic content hash; counters are derived, never blindly incremented. A candidate-mutated revision is committed only when its exact revision token is present in the evaluation ledger.
- **Authority:** the confirmation-backed view owns partial/active semantic episode membership and the persisted anchor. A provisional raw revision never marks a candidate complete or suppresses its replay; its token lets the same candidate reuse and repair that state. Incident link tables remain authoritative for confirmed incident membership, and the input ledger remains authoritative for evaluation completeness.
- **Retention:** an episode becomes logically inactive only after its window and allowed-lateness horizon. Physical cleanup is a reviewed administration operation, not correctness-dependent asynchronous TTL behavior.

Member arrays require a rule-level maximum. Overflow must fail visibly and leave the triggering input unledgered rather than truncate evidence silently.

### `fusion.correlation_scope_bootstrap_confirmations`

- **Columns:** engine/rule/positive integer version/fingerprint, deterministic `scope_bootstrap_token`, expected rule-state hash/revision, and confirmation time.
- **Engine:** immutable `MergeTree`.
- **ORDER BY:** `(engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint, scope_bootstrap_token)`.
- **Partitioning:** none; one small logical row per scope bootstrap.
- **Idempotency/update:** after writing bootstrap rule state, the engine reads back its exact token/hash/revision, writes this deterministic confirmation, and reads the confirmation back before polling candidates. Duplicate physical confirmation rows collapse logically by the complete key.
- **Authority:** confirms only immutable scope bootstrap state. It is not an input-evaluation ledger, cannot confirm candidate-mutated state, and cannot claim input completeness.
- **Retention:** retain with the rule scope and its ledger.

### `fusion.correlation_schedule_state`

- **Columns:** engine/rule/positive integer version/fingerprint, candidate cursor occurrence/observation time/kind/ID, newest eligible position, exact unevaluated count, nullable oldest unevaluated observation time, oldest unevaluated age seconds, per-cycle evaluated/matched/failed counts, incident/link counts, processing duration/rate, consecutive drain cycles, update time, and revision.
- **Engine:** `ReplacingMergeTree(revision)`.
- **ORDER BY:** `(engine_id, correlation_rule_id, correlation_rule_version, correlation_scope_fingerprint)`.
- **Partitioning:** none; this is small operational state.
- **Idempotency/update:** update only after the applicable evaluation-ledger identity is visible. A crash before this update leaves a stale cursor, which changes scheduling only because the ledger anti-join remains authoritative.
- **Empty-backlog convention:** `unevaluated_input_count = 0`, `oldest_unevaluated_observed_at = NULL`, and `oldest_unevaluated_age_seconds = 0.0`.
- **Retention:** same scope lifecycle as rule state; it is never a completeness authority.

### `fusion.incident_status_transitions`

- **Columns:** deterministic idempotency token/transition ID, incident ID, prior and target status, requested/applied UTC times, fixed local-admin actor type, resulting incident revision, and validation ID.
- **Engine:** immutable `MergeTree`.
- **ORDER BY:** `(incident_id, applied_at, transition_id)`.
- **Partitioning:** `toYYYYMM(applied_at)`.
- **Idempotency/update:** one logical row per transition token; only the serialized correlation-engine mutation path writes it.
- **Authority:** durable audit of lifecycle changes. The current incident revision remains the serving state.
- **Retention:** aligned with the incident; no independent v0.6 TTL.

## Timeline read model

The incident timeline is a hybrid model:

1. Select the highest confirmation-backed incident revision, then union only logical detection/event links whose introduction tokens are backed by the exact evaluation ledger.
2. Use the immutable link snapshot for the default dashboard row.
3. Join to live `fusion.detections` or `fusion.sysmon_events` only for an authorized drill-down while the source row remains retained.
4. Order by `(occurred_at, input_kind, input_id)` so equal timestamps are deterministic.

The timeline exposes:

| Field | Source |
| --- | --- |
| timestamp | link `occurred_at` |
| visible/detected time | link `observed_at` |
| source type | link snapshot |
| detection ID | detection link; blank for event context |
| rule | Sigma rule for detections, normalized action for events |
| host / user / source IP / destination IP | bounded snapshot |
| severity | detection snapshot or empty for context events |
| summary | rule-controlled bounded text, never raw JSON |

Persisting the small snapshot is justified because current source rows have finite TTLs. Persisting full source evidence is not justified and would increase sensitive-data duplication.

## Read-model invariants

- One logical confirmation-backed current incident per `incident_id`.
- One logical link per `(incident_id, tagged input identity)`.
- After the confirmation barrier, `detection_count` and `event_count` equal distinct authoritative links in the current incident revision.
- Incident MITRE arrays are sorted unique unions.
- `first_seen`/`last_seen` equal the minimum/maximum link occurrence time.
- Lifecycle timestamps agree with status.
- A ledgered input never points to an incident, link, rule state, or episode state that was not confirmed first.
- Physical duplicate rows never appear as duplicate incidents or timeline items in Grafana.

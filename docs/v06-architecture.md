# Fusion v0.6 Correlation and Incident Architecture

Status: **frozen v0.6 architecture contract**. This document defines architecture only. It does not authorize runtime code, ClickHouse migrations, or release activity.

## Objective

Fusion v0.6 adds a post-detection correlation layer that turns related detections and selected normalized events into durable incidents:

```text
Windows / Linux / Suricata / generic telemetry
                    |
                    v
                  Vector
                    |
                    v
          fusion.sysmon_events
             |                 \
             v                  \ selected normalized events
     Fusion Detection Engine     \
             |                    v
             v          Fusion Correlation Engine
      fusion.detections -------->|
                    |              |
                    v              v
          correlation state   fusion.incidents
                              |
                              v
                 Fusion Incidents dashboard
```

The correlation service is downstream and independent. Detections are its primary input; narrowly selected normalized events supply required non-alert context such as SSH success and endpoint-local IP provenance. **Detections assert suspiciousness; approved normalized events only prove non-alert facts or time-bounded entity relationships.** Stopping correlation must not stop Vector, ClickHouse ingestion, or Sigma detection. It has no public listener and makes no runtime Internet requests.

## Frozen component boundary

The future `fusion-correlation-engine` should be a single-instance, polling service for the v0.6 lab. It should:

1. Load and fail-closed validate repository-managed correlation YAML.
2. Compile each rule into a bounded in-process evaluation plan.
3. Enroll eligible logical inputs from `fusion.detections` and, only where an approved rule requires context, `fusion.sysmon_events`.
4. Anti-join candidates against a persisted per-rule evaluation ledger. All logical detections are eligible; normalized events enter this union only when they match at least one compiled `source: event` selector.
5. Query a bounded occurrence-time window around each candidate and evaluate the rule.
6. Apply the frozen incident-first write contract below, confirming every deterministic effect before marking the input evaluated.
7. Emit payload-free cycle telemetry and persist scheduling/lag telemetry only after the evaluation-ledger write.

Correlation rules never contain SQL. SQL shapes, selected columns, table names, limits, and ordering are owned by trusted engine code. Rule values are data bound to an allowlisted evaluator.

## Why correlation consumes two input kinds

Detections remain the primary security signal, but detections alone cannot represent every required v0.6 scenario. In particular, the initial SSH sequence needs a successful authentication record, while v0.5 intentionally detects only the failure. Under the current schema, the initial cross-source rule requires a normalized direction-safe endpoint network event to prove time-bounded host/IP ownership; a hostname or arbitrary IP field is not sufficient.

The engine therefore uses one logical input envelope:

| Envelope field | Detection source | Event source |
| --- | --- | --- |
| `input_kind` | `detection` | `event` |
| `input_id` | `detection_id` | `event_uid` |
| `occurred_at` | `source_event_time` | `event_time` |
| `observed_at` | `detected_at` | `ingested_at` |
| `platform`, `source_type`, `host_name`, `user_name` | normalized detection fields | normalized event fields |
| `source_ip`, `destination_ip` | normalized detection fields | normalized event fields |
| `severity`, `rule_id`, MITRE fields | detection values | unavailable for correlation classification; factual context fields only |

The tagged identity is `input_kind + NUL + input_id`; the two namespaces must never be treated as interchangeable. Physical ClickHouse replays are collapsed to one logical ID before a batch limit is applied. Canonical `observed_at` is the minimum persisted visibility time across physical rows for that logical ID, so replay cannot refresh lateness. Conflicting immutable occurrence or entity values for one logical ID fail visibly instead of being selected arbitrarily.

Event inputs are not a back door to raw telemetry or a second detection language. Every correlation rule and every created incident must include at least one linked detection. Event selectors may provide only an approved factual sequence stage or entity/provenance context; they cannot create an incident alone, supply suspiciousness, raise severity, add MITRE classifications, or count as a distinct suspicious rule. If an event requires suspicious classification, that classification belongs in a reviewed detection rule and `fusion.detections`. v0.6 rules may select only documented normalized fields; `raw_json`, command payloads, arbitrary JSON paths, and source-specific untrusted field names are unavailable.

## Evaluation and write contract

For each rule scope and logical candidate, the required order is:

```text
candidate selected by ledger anti-join
  -> bounded context window evaluated
  -> deterministic incident identity and intended membership derived
  -> write/update incident idempotently
  -> write evidence links idempotently
  -> write correlation rule and episode state idempotently
  -> read back and confirm incident, links, and state
  -> correlation-evaluation ledger row acknowledged
  -> diagnostic cursor and cycle telemetry updated
```

This exact order is normative for a match, update, or enrichment. The incident snapshot is built from the canonical intended membership in memory even though the authoritative link rows are written next. A no-match or partial sequence has no dummy incident/link write: the engine writes any required rule/episode state, confirms that state, writes the evaluation ledger, and only then advances scheduling state.

Confirmation is a deterministic read-after-write barrier. Before ledgering an input, the engine must read back the expected current `incident_id`, `state_hash`, and revision when an incident exists; every intended logical link identity; and the expected rule/episode state identities and state hashes. Missing or mismatched effects leave the input unledgered and retryable. All writes use acknowledged ClickHouse semantics; asynchronous inserts may not report success before server acknowledgement.

This is intentionally at-least-once processing with idempotent effects. ClickHouse does not provide a transaction spanning these tables. A crash may leave an unconfirmed incident without all links, or complete effects without a ledger row. Replay re-evaluates the same logical input, derives the same incident/link/state identities, no-ops an unchanged incident `state_hash`, fills missing effects, reconfirms them, and writes one logical ledger identity. A crash after the ledger but before the cursor is harmless because the ledger anti-join—not the cursor—prevents re-evaluation. Replay after any intermediate failure must converge to one logical incident and one logical evidence membership.

All dependent writes must use acknowledged ClickHouse semantics. The runtime must not globally disable asynchronous inserts; if asynchronous inserts are enabled, it must require server acknowledgement before advancing to the next dependent write.

## Completeness, scheduling, and restart model

Completeness is represented by `fusion.correlation_evaluated_inputs`, with the exact logical key:

```text
(engine_id, correlation_rule_id, correlation_rule_version,
 correlation_scope_fingerprint, input_kind, input_id)
```

`correlation_rule_version` is a positive integer and is a separate key dimension. A timestamp checkpoint is not sufficient and must not be used as the authority.

Each correlation rule has an independent scope fingerprint covering:

- correlation engine/compiler version;
- rule schema and canonical compiled semantics;
- normalized-field/entity mappings; and
- incident scoring and MITRE mappings used by the rule.

The human rule version, descriptive prose, repository-relative source path, and file hash are not bytes in the semantic fingerprint. Version is the explicit adjacent scope key; path and full-file hash remain audit metadata. Any behavior change still changes the fingerprint, and CI also requires a version increment.

The human `correlation_rule_version` remains visible in incidents, while the fingerprint prevents semantically different rule content from sharing evaluation state.

`fusion.correlation_rule_state` stores the fixed enrollment floor and semantic rule-scope state. `fusion.correlation_episode_state` persists bounded per-group partial/active membership and an immutable incident anchor, including state needed to prevent one input set from being reused across episodes. Those semantic tables are written and confirmed before the ledger. A separate `fusion.correlation_schedule_state` stores the rotating candidate cursor and lag/cycle telemetry and is updated only after the ledger. None of these state tables proves completeness. A candidate is complete only when its exact ledger key exists. A repeatedly failing candidate remains unledgered, is retried after bounded cursor rotation, and cannot permanently starve valid candidates behind it.

On restart, the engine reloads rule scopes and state, then resumes the anti-join. Stale or missing schedule state may change scan order only. If a crash occurred after an incident write but before the ledger write, replay computes the same incident, link, and episode identities and produces no logical amplification.

The first enrollment floor for a rule scope is fixed from the configured lookback. A row observed after that floor remains eligible even when its occurrence timestamp is older. Any new `(correlation_rule_version, correlation_scope_fingerprint)` pair receives a new bounded scope, including a version-only bump; it does not silently claim that another pair evaluated it. Returning from scope pair A to an earlier pair restores A's own persisted state.

See [v06-correlation-model.md](v06-correlation-model.md) for the detailed replay and late-input rules.

## Frozen time, episode, and entity contract

- `occurred_at` is the only clock used for threshold membership, sequence ordering, join span, canonical match selection, and episode boundaries. It is `source_event_time` for a detection and `event_time` for a normalized event.
- `observed_at` is the stable persisted ingestion/visibility clock: `detected_at` for a detection and `ingested_at` for an event. It is used only for enrollment, recovery eligibility, backlog age, and allowed-lateness decisions. It never moves a correlation window or episode anchor.
- Threshold and join spans are inclusive at exactly `window`. Sequence stages must be strictly ordered by occurrence time, while their first-to-last span is inclusive at exactly `window`. One millisecond beyond a window is outside it.
- On first qualification, physical duplicates are collapsed, unique tagged inputs are stably ordered, one canonical minimum qualifying set is selected, and its type-specific anchor is persisted. The anchor and the episode's single-width occurrence interval never move.
- Related activity updates that episode only when its occurrence is inside the inclusive episode interval and its observation time is within the applicable lateness deadline. Unowned activity beyond the occurrence boundary starts a new partial episode and creates a new deterministic incident only if it independently qualifies.
- Canonical users, hosts, and IPs follow the normative rules in [v06-correlation-model.md](v06-correlation-model.md). In particular, short hostnames do not automatically equal FQDNs, IPv4-mapped IPv6 collapses to IPv4, and empty required identities never form a group.
- Cross-source host/IP correlation requires a direction-safe, time-bounded endpoint ownership fact within the same occurrence window. Hostname or IP string equality without that evidence is insufficient.

## Incident ownership and serving model

`fusion.incidents` stores the current versioned incident summary. Durable many-to-many relationships live in link tables:

- `fusion.incident_detection_links` for detections;
- `fusion.incident_event_links` for normalized event context.

The link tables are authoritative for membership. `related_detection_ids` is exposed as a derived array in an incident query/view rather than stored as a second authority in the incident row. Each link also contains a small immutable timeline snapshot so a useful incident timeline survives the existing source-event and detection TTLs without duplicating raw evidence. Incident revisions, newly introduced links, and candidate-mutated semantic-state revisions carry the same deterministic evaluation revision token. Revision-preserving sorting keys retain the last confirmed incident/state predecessor while a higher provisional revision exists. Serving/committed-state views expose candidate effects only after the exact evaluation-ledger token exists; lifecycle revisions require their audit row. Immutable scope bootstrap state is the sole exception and requires a separate deterministic bootstrap-confirmation row before polling begins. An already confirmed link is never overwritten with a new unconfirmed introduction token.

Incident rows use deterministic IDs and append-only replacement revisions. The v0.6 deployment remains a single writer; HA leases and multi-writer conflict resolution are out of scope.

Minimal acknowledge/close operations should use a restricted local command over a container-private Unix socket to that same writer. Grafana stays read-only and there is no public case-management API. An immutable `fusion.incident_status_transitions` table preserves the small lifecycle audit without adding comments, assignments, or workflow features.

## Failure isolation and security defaults

- Correlation failure cannot interrupt telemetry ingestion or Sigma detection.
- Invalid or unsupported rules prevent that ruleset from starting; constructs are never approximated.
- Per-input failures remain visible and unledgered. They are not silently dropped.
- Candidate and context queries have configured row, stage, group, and time-window bounds.
- Blank group keys are excluded unless a rule explicitly uses a safe documented missing-value policy.
- The service exposes no host port, runs without elevated capabilities, uses a read-only root filesystem, and writes only to required ClickHouse tables.
- Logs contain IDs, counts, durations, lag, and rule identifiers, not raw event bodies, credentials, command lines, or evidence payloads.
- `evidence_json` contains a compact correlation explanation and IDs, not `raw_json`.
- A future least-privilege ClickHouse account is preferred. Reusing the current lab credential is a documented lab limitation, not a production recommendation.

## Operational telemetry

Each rule scope must expose, through structured logs and `fusion.correlation_schedule_state`:

- rule ID, version, and scope fingerprint;
- newest eligible input position and observation time;
- exact unevaluated logical-input count;
- oldest unevaluated observation time and age;
- candidates evaluated, matched, and failed in the cycle;
- incidents created and updated;
- detection and event links written;
- processing duration and effective inputs per second;
- cursor position and consecutive drain-cycle count.

The exact ledger anti-join count is the completeness metric. Cursor lag is diagnostic only. When that count is zero, `oldest_unevaluated_observed_at` must be null and `oldest_unevaluated_age_seconds` must be stored/reported as `0.0`. Metrics must be suitable for later Grafana queries without adding Prometheus or another major component in v0.6.

## Future Fusion Incidents dashboard

Grafana should provision one read-only `Fusion Incidents` dashboard with:

- open incident count (`new` plus `acknowledged`);
- severity distribution;
- incidents created over time;
- incident type distribution;
- affected hosts and users;
- MITRE technique frequency;
- cross-source incident count and list;
- a filterable incident table; and
- an incident detail/timeline panel ordered by occurrence time and stable input identity.

Filters should include time, status, severity, incident type, host, user, correlation rule, tactic, and technique. Queries must resolve replacement rows deliberately and aggregate link identities without displaying duplicate physical rows. Grafana is a viewer in v0.6; lifecycle mutation in the dashboard is not part of this design.

## Lab-scale performance boundaries

The v0.5.2 baseline proves exact 100K detection evaluation and five-minute sustained 100/250/500 EPS ingestion in a single-node lab. It does not prove that multi-window correlation has the same capacity. The correlation engine must preserve correctness under bounded work before optimizing throughput.

Frozen v0.6 release SLOs are defined in [v06-acceptance-plan.md](v06-acceptance-plan.md). In summary:

- exact ledger completeness, zero logical duplicates, zero final backlog, and zero oldest-backlog age after quiescence;
- idle processing latency measured from ClickHouse visibility, not source event time;
- exact 1,001 same-timestamp input handling;
- exact 10K backlog drain within 60 seconds with healthy services;
- bounded query/window sizes and no unbounded busy loop; and
- observable backlog age whenever input exceeds tested capacity.

No enterprise-scale, HA, or distributed-correlation claim is made.

## Principal risks

1. **No cross-table transaction.** Incident, link, state, and ledger writes can be partially visible. The frozen incident-first order, confirmation barrier, ledger-last completeness rule, confirmation-aware serving view, and deterministic replay are mandatory.
2. **Ledger and rule-scope growth.** A per-rule ledger multiplies identities by rule count. Retention cannot be enabled independently of retained source records without re-evaluation risk.
3. **ClickHouse revision semantics.** Replayed physical duplicates may remain until merges, while distinct incident/semantic-state revisions are deliberately retained. Correctness queries must filter confirmation tokens and select the highest confirmed revision.
4. **Hot groups.** A shared host, username, or IP can create large context windows. Limits and candidate rotation must fail visibly rather than truncate silently.
5. **Clock skew and event-time boundaries.** Correlation uses occurrence time with deterministic tie-breaking, while processing SLOs use observation time.
6. **Entity ambiguity.** Usernames lack a universal realm, and an IP can represent NAT, infrastructure, or either side of a connection.
7. **Episode identity under late arrival.** IDs are deterministic for a canonical minimal qualifying set and stable after creation, but competing extra inputs can make a different from-empty visibility history choose a different first qualifying set. v0.6 does not rename or merge existing incidents.
8. **Closed-incident enrichment.** Late evidence may alter counts/severity while status remains closed; this requires explicit audit revisions and a bounded grace period.
9. **Rule-version replay.** A new version/fingerprint pair creates a new evaluation scope and can intentionally create pair-specific incidents for old lookback inputs.
10. **Serving cost.** `FINAL`, anti-joins, arrays, and timeline joins are acceptable only within measured lab bounds.

## Frozen design decisions

| Decision | Frozen v0.6 choice | Why it must be frozen |
| --- | --- | --- |
| Correlation inputs | Tagged detections plus explicitly selected normalized context/sequence events; every incident includes a detection | Keeps suspicious classification in the detection layer |
| Completeness scope | Engine + rule ID + positive integer version + semantic fingerprint + input kind + input ID | Prevents one rule failure/change or input namespace from corrupting completeness |
| Cursor role | Post-ledger scheduling/diagnostic state only; ledger anti-join is authoritative | Prevents a repeat of positional-checkpoint loss |
| Write order | Evaluate, derive ID, incident, links, rule/episode state, confirm, ledger, then schedule state | Makes every crash boundary replayable without logical amplification |
| Rule language | Versioned YAML with three bounded condition types and allowlisted fields/operators | Parser, tests, and security boundary depend on it |
| Incident membership | Link tables authoritative; related-ID arrays derived | Avoids two conflicting membership authorities |
| Timeline | Hybrid: links plus minimal immutable snapshots | Preserves investigation context across current TTLs without copying raw events |
| Incident identity | Rule/version + compiled semantic fingerprint + canonical group + persisted immutable episode anchor | Prevents unversioned semantic edits from aliasing an old incident and is required for replay/deduplication |
| Rule version behavior | Every new `(version, fingerprint)` pair creates a bounded evaluation scope, including version-only bumps; old incidents are not rewritten | Prevents semantic ambiguity |
| Episode boundary | One immutable `window`-wide occurrence interval beginning at the canonical set's earliest occurrence; owned inputs are not reused | Prevents sliding windows and adjacent duplicate-looking incidents |
| Closed incidents | `new -> acknowledged -> closed`; no reopen; old-episode enrichment ends no later than immutable `closed_at + allowed_lateness`; only unowned occurrence outside the old interval may form a new episode | Keeps closure meaningful and lateness bounded |
| Time semantics | UTC millisecond occurrence time only for correlation; ingestion/visibility time only for enrollment, recovery, lateness, and SLOs; inclusive boundary with stable tie-break | Eliminates boundary and clock interpretations |
| Cross-source host/IP proof | Direction-safe endpoint ownership fact whose occurrence participates in the same rule window; never simple string equality or a timeless cache | Avoids guessing host ownership from an unrelated or stale IP |
| User identity | Platform-aware canonical full principal; syntax/realm retained and no unreviewed alias inference | Avoids pretending names in different identity namespaces are equal |
| Host identity | Case/trailing-dot variants normalize; short name, FQDN, and aliases remain distinct without trusted mapping | Avoids cross-host false correlation |
| IP identity | Canonical IP parsing, including IPv4-mapped IPv6 collapse; multi-IP ownership remains fact-based and time-bounded | Makes joins deterministic without inventing asset inventory |
| Retention | No independent v0.6 ledger/link TTL until a relationship-safe retention contract is approved | Prevents silent re-evaluation and broken timelines |
| Runtime topology | One correlation writer, no public port, no HA | Defines revision and conflict assumptions |
| Lifecycle mutation | Restricted local command to the serialized writer plus immutable transition audit; Grafana read-only | Prevents correlation/status lost updates without creating a public case API |
| Release SLOs | Exact targets in the acceptance plan, including p95 <=12 seconds, 10K <=60 seconds, and zero drained backlog/age | Creates measurable lab release gates without enterprise claims |

Implementation must not begin until these decisions, the schemas in [v06-incident-model.md](v06-incident-model.md), the rule subset in [v06-correlation-model.md](v06-correlation-model.md), and the gates in [v06-acceptance-plan.md](v06-acceptance-plan.md) complete design review.

## Explicitly out of scope for v0.6

- SOAR and automated remediation
- email, Slack, or other notifications
- AI/LLM incident summaries
- case comments and attachments
- assignment, ticketing, and workflow automation
- multi-tenancy and RBAC
- HA or distributed correlation
- external threat-intelligence enrichment
- production case-management APIs

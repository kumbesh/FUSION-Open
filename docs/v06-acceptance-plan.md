# Fusion v0.6 Correlation and Incident Acceptance Plan

Status: **frozen v0.6 acceptance contract**. These are release gates for future implementation. No v0.6 runtime, migration, or release is authorized by this document.

## Acceptance principles

- Correctness is measured on unique logical input, incident, and link identities—not physical `ReplacingMergeTree` row counts.
- The per-rule correlation evaluation ledger is the completeness authority, keyed by engine, rule ID, positive integer rule version, semantic fingerprint, input kind, and input ID. Cursor/checkpoint position is diagnostic only.
- Detection inputs include all eligible logical detections. Event inputs include only events matching at least one compiled, allowlisted `source: event` selector; v0.6 must not create a second ledger for every raw telemetry row.
- Detections assert suspiciousness. Approved normalized events provide only factual sequence or time-bounded relationship context, and every incident must include at least one detection.
- Correlation membership, order, anchor, and boundaries use authoritative occurrence time only. Persisted ingestion/visibility time is used only for enrollment, recovery/lateness eligibility, latency, and backlog age.
- Effectful processing follows incident-first ordering and confirms incident, links, and semantic state before the ledger; scheduling state advances after the ledger.
- Synthetic fixtures, controlled real telemetry, migration evidence, and performance evidence are reported separately.
- No gate may be made green by deleting buffers, state, ledger rows, incidents, links, or existing Docker volumes.
- A failed gate blocks release. No `v0.6.0` tag is created until PR CI, manual gates, merge, and post-merge main CI all pass.

## Frozen lab SLOs

These are required single-node lab release targets, not enterprise capacity claims. The implementation test-host profile must be recorded alongside results.

| Measure | Required release target |
| --- | --- |
| Eligible-input completeness | For every active `(engine, rule ID, version, fingerprint)` scope, `uniqExact(input_kind, input_id)` in the ledger equals the independently computed eligible tagged-input union after quiescence; `unevaluated_input_count = 0` |
| Drained-backlog telemetry | After every successful drain, `unevaluated_input_count = 0`, `oldest_unevaluated_observed_at IS NULL`, and `oldest_unevaluated_age_seconds = 0.0` |
| Incident deduplication | zero additional logical incident IDs for the same rule/group episode after replay or restart; zero logical duplicate incidents |
| Link deduplication | zero duplicate logical `(incident_id, detection_id)` or `(incident_id, event_uid)` links |
| Idle correlation-only latency | with input already visible in ClickHouse and no backlog: at least 30 detection candidates and 30 allowlisted context-event candidates measured from canonical earliest `observed_at` to evaluation-ledger visibility, plus 30 qualifying mixed-join terminal candidates measured to confirmation-backed incident visibility; nearest-rank p95 for each path and combined <=12 seconds, maximum <=15 seconds at the 10-second poll |
| Controlled end-to-end latency | qualifying incident visible within 30 seconds of the terminal input becoming visible to its upstream table |
| Same-timestamp page boundary | detection-input, approved context-event-input, and mixed/tagged-namespace runs each ledger exactly 1,001 inputs; second page begins within 1 second of the first full 1,000-input page; backlog and oldest age return to zero within 15 seconds |
| Preloaded backlog | exact 10,000-input ledger equality, final backlog zero, and oldest unevaluated age zero within 60 seconds of correlation-engine start |
| Nonmatching workload safety | designated nonmatching 1,001 and 10K workloads end with zero logical incidents, zero detection links, and zero event links |
| Sustained correlation input | 100 eligible correlation inputs/second for five minutes; no loss/duplicates/restarts/OOM; zero backlog within 30 seconds after sender completion |
| Existing pipeline coexistence | v0.5.2 100K and 500 source-EPS controls remain exact; same-host/same-code completion degradation with correlation active <=25% versus an immediately preceding control |
| Resource envelope | initially test at 1 CPU and 512 MiB for the correlation service; no OOM, automatic restart, or health failure; report observed CPU/RAM |
| Query behavior | no unbounded query, group, array, or busy loop; report p50/p95/max candidate, context, state, and dashboard query duration/bytes |

The v0.5.2 values—44.119 seconds for exact 100K detection evaluation and 9.798 seconds post-send drain at 500 source events/second—are provenance, not a cross-host regression oracle. Source EPS and eligible correlation-input EPS are different units. Rates above 100 correlation inputs/second are characterized at 250 and 500 only after the 100-input gate passes; they are not release SLOs unless explicitly reviewed.

## Gate 0 — architecture freeze

The implementation must conform to these frozen decisions before runtime work begins:

- typed detection plus narrowly allowlisted event inputs;
- exact rule schema and operator/field allowlists;
- per-rule semantic fingerprint and version-change behavior;
- authoritative occurrence time, ingestion-only lateness/recovery use, and inclusive window boundaries;
- strict later-time sequence ordering;
- platform-aware principal, hostname/FQDN, IP, multi-IP, ownership, and blank-key normalization;
- canonical episode-anchor selection, immutable single-window occurrence interval, non-reuse rule, observation-time lateness deadline, and late-overlap owner;
- time-bounded cross-source endpoint IP ownership provenance;
- exact incident-first write/confirmation/ledger/cursor order and confirmation-aware current-state query model;
- lifecycle ownership and closed-incident behavior;
- severity/confidence formulas and MITRE tactic-ID source;
- evidence snapshot and coordinated retention policy;
- batch/poll/fairness/retry bounds; and
- the frozen SLOs above and recorded test-host profile.

The four architecture documents should have no unresolved contradiction before a migration or runtime branch starts.

## Gate 1 — static rule and security validation

Required unit/fixture coverage:

- valid examples for threshold, sequence, and join;
- duplicate rule IDs/versions and duplicate YAML keys;
- unknown keys, fields, sources, operators, and title placeholders;
- malformed/negative/zero/excessive window, lateness, thresholds, stages, and selectors;
- unsafe YAML tags, aliases, anchors, merge keys, and oversized/deep input;
- explicit rejection of `sql`, `query`, condition strings, code, regex, glob, raw/evidence JSON, environment expansion, and arbitrary field references;
- deterministic compiler plan and semantic fingerprint;
- canonical host, full user, IPv4, and IPv6 keys;
- down-level versus UPN versus bare principals, Windows versus Linux casing, FQDN/trailing-dot versus short-name behavior, and IPv4-mapped IPv6;
- multiple simultaneous host IPs, stale ownership, IP reuse by another host, and time-window ownership expiry;
- blank/invalid entity exclusion with an observable counter;
- rejection of event-only rules, event thresholds, sequences with no detection stage, joins with no detection input, and event-derived severity/MITRE/suspicious-rule counts;
- bounded context result overflow fails visibly rather than truncating; and
- rule content never becomes a SQL identifier, expression, sort, limit, or table name.

Every shipped rule requires positive and negative fixtures. Rule validation must finish without ClickHouse writes or network access.

## Gate 2 — incident model unit tests

Required tests:

- deterministic incident and link identity vectors;
- physical duplicates collapse before canonical-set selection; arrival-order permutations of the same minimal qualifying set produce the documented stable incident ID and immutable anchor;
- exact threshold, sequence, and join canonical-anchor vectors plus proof that late earlier evidence cannot move the anchor or one-window episode interval;
- owned inputs cannot seed a second incident for the same rule/group episode, while unowned post-boundary inputs can independently qualify a new deterministic episode;
- counts, first/last seen, source families, and MITRE arrays are recomputed from distinct logical links;
- severity and confidence examples for all four initial rules;
- `related_detection_ids` is derived from links and sorted unique;
- evidence JSON is bounded/versioned and excludes raw JSON and secrets;
- current-state read selects one highest revision;
- revision-preserving incident/rule/episode keys retain the last confirmed predecessor through ClickHouse merges while a higher provisional revision exists;
- deterministic scope-bootstrap state is invisible until its dedicated confirmation row exists, contains no input completion/membership, and polling cannot start before confirmation;
- allowed lifecycle transitions and idempotent same-state requests;
- forbidden transition/reopen attempts;
- lifecycle-token replay and exact reconstruction of a missing immutable transition audit row;
- correlation update preserves `acknowledged` and its timestamp;
- bounded late enrichment follows the approved occurrence interval and observation-time deadline; and
- confirmation-aware serving hides incident revisions whose correlation or lifecycle revision token is not yet backed by a ledger/audit row; and
- physical replacement rows never appear as duplicate incident/timeline entries.

## Gate 3 — migration validation

When migrations exist, test both PowerShell 5.1 and PowerShell 7/Bash paths as applicable:

1. Fresh empty installation.
2. Upgrade from the exact v0.5.2 schema while preserving source events, detections, evaluation ledgers, checkpoints, and ruleset scopes.
3. Apply every v0.6 migration twice to prove idempotency.
4. Verify exact columns, types, engines, ordering keys, immutable defaults, and initial empty state.
5. Insert sentinel incident/link/ledger/state rows with command-scoped acknowledged validation inserts.
6. Reapply migrations and prove sentinels remain logically unchanged.
7. Run the existing full v0.5.2 validation unchanged.

No global ClickHouse async-insert setting is changed.

## Gate 4 — processing, restart, and crash consistency

The harness must first assert the normative effect order from captured adapter calls:

```text
evaluate
  -> derive deterministic incident identity
  -> write/update incident
  -> write evidence links
  -> write correlation rule/episode state
  -> read back and confirm all expected effects
  -> write evaluation ledger
  -> update scheduling cursor/diagnostic state
```

No-match and partial-sequence cases omit nonexistent incident/link effects, confirm required semantic state, then write the ledger and schedule state. Three deterministic crash tests are mandatory:

1. crash after the incident write is acknowledged but before any evidence-link write;
2. crash after exact evidence links and rule/episode state are written, including cuts immediately before and after the confirmation barrier, but before the evaluation-ledger write; and
3. crash after the evaluation-ledger write is acknowledged but before scheduling cursor/diagnostic state is updated.

For every cut, restart/replay must produce the same `incident_id`, immutable anchor, incident `state_hash`, exact logical evidence membership, one logical link per tagged input, one logical evaluation-ledger key, zero duplicate logical incidents, a progressing eventual cursor, final backlog zero, and oldest unevaluated age zero. Separately inject ambiguous acknowledgements/timeouts at the incident, link, rule-state, episode-state, and ledger boundaries. Physical replacement rows may exist after an ambiguous write, but current logical identities and confirmation-aware serving results must remain exact.

At the links/state-before-ledger cut, query the serving views before restart: the last confirmed incident revision and timeline must remain unchanged, provisional links must be absent, and provisional semantic state must not suppress the unledgered candidate. After replay and ledger confirmation, the new revision, links, and state must appear exactly once.

Force a ClickHouse merge/optimization while that provisional revision exists and repeat the same assertions; the revision-preserving key must prevent the confirmed predecessor from disappearing.

Test scope bootstrap separately: crash after bootstrap rule-state write but before its confirmation row and prove no candidate polling occurs; restart must verify/write/read the deterministic confirmation exactly once, then begin polling. A bootstrap confirmation can never stand in for an evaluation-ledger identity.

Also test ClickHouse unavailability/recovery and the confirmation barrier returning a missing or mismatched effect; the input must remain unledgered until replay repairs and confirms it.

Lifecycle fault injection separately stops after the incident revision containing its transition token/prior state and before the immutable transition audit write; replay must restore exactly one audit row without changing the resulting incident revision.

After restart/replay, each case must converge to the same logical incident, links, semantic state, and ledger. No missing effect may exist behind a completed ledger identity.

Also prove:

- empty/partial backlog uses the normal poll;
- full batches drain immediately with a bounded shutdown-aware cooperative yield;
- clean shutdown during drain;
- exponential retry/backoff remains bounded;
- a repeatably failing input stays visible/unledgered but cannot starve later pages;
- scope pair A→B→A, including a version-only change with unchanged fingerprint, restores A's enrollment/rule/episode/schedule state;
- deleting/resetting a diagnostic cursor cannot create false completeness;
- a duplicate physical detection/event is one logical correlation input; and
- a previously ledgered input remains available as context for a later candidate.

## Gate 5 — late and out-of-order matrix

Test every relevant permutation:

- detection arrives late with occurrence time below cursor/checkpoint;
- SSH success arrives after failures and failures arrive after a previously visible success;
- Suricata first, endpoint first, and endpoint-IP context last;
- same input replayed before and after engine restart;
- physical replay of one logical ID with a later visibility time retains the earliest canonical `observed_at` and the same lateness/episode outcome; conflicting immutable occurrence or entity values fail visibly rather than winning by merge order;
- input exactly on the rule-window boundary and one millisecond outside;
- input exactly at `episode_window_end` updates the old episode, while `episode_window_end + 1 ms` enters new partial state; changing only `observed_at` never moves either occurrence boundary;
- occurrence inside the old episode but observation after its lateness deadline is ledgered as `no_match` plus `late_outside_boundary`, with no mutation or cloned incident;
- unowned occurrence after the episode boundary independently qualifies a new deterministic episode without reusing old owned inputs;
- threshold/join equal-millisecond records;
- equal-millisecond sequence records do not claim ordering;
- `DOMAIN\User`/case variants, UPN variants, and bare principals follow the frozen distinct-namespace rules; Windows and Linux casing behavior differs as specified;
- hostname case/trailing-dot variants match, while short/FQDN aliases do not match without trusted mapping;
- IPv4-mapped IPv6 matches canonical IPv4; simultaneous multi-IP, stale ownership, and later IP reuse by another host cannot create an unproven join;
- rule semantic version/fingerprint changes;
- late evidence updating `new`, `acknowledged`, and `closed` episodes under the frozen policy;
- late evidence overlapping two incidents selects the documented deterministic owner and emits a collision metric; and
- implausible future timestamps cannot advance state or expire valid groups silently.

Inputs outside the reconciliation horizon must receive explicit `evaluation_action` and `lateness_status` values plus a metric; they cannot vanish from accounting or use ingestion time as a correlation-time fallback.

## Gate 6 — four automated scenario suites

### A. SSH brute force followed by success

- 4 failures + success: no incident.
- 5 failures without success: no incident.
- success before failures: no incident.
- 5 unique failure detections + matching success event within 5 minutes: exactly one incident.
- wrong host, user, or source IP: no incident.
- duplicate failure does not satisfy count.
- five raw authentication-failure events without their Sigma detections do not qualify; events cannot assert brute-force suspiciousness.
- expected five detection links plus one event link, ordered timeline, high severity, T1110, deterministic ID.
- later/replayed/late input follows the documented episode policy without amplification.

### B. Multiple suspicious detections on one host

- two medium-or-higher detections from distinct rules on one host within 10 minutes: exactly one incident.
- same rule twice, different hosts, low-only, blank host, or out-of-window: no incident.
- raw endpoint events without two linked detections cannot satisfy the host rule.
- exact 10-minute boundary: match; plus one millisecond: no match.
- third distinct detection updates the same ID and recomputes counts/MITRE values.

### C. Suricata and endpoint

- real-shaped Suricata detection + endpoint detection + proven endpoint-local-IP event within 10 minutes: exactly one incident.
- network-first and endpoint-first: same logical incident.
- wrong host binding, no IP intersection, two Suricata inputs, invalid/blank IP, or out-of-window: no incident.
- a raw Suricata alert event without its Suricata detection, hostname/IP equality without ownership evidence, stale ownership, or IP ownership by another host does not qualify.
- evidence records which normalized field/source established the local IP.
- exactly two detection links plus the required endpoint context event link.

### D. Multiple rules for one user

- two distinct rule IDs for the same canonical `(platform, user_name)` within 15 minutes: exactly one incident.
- same rule twice, different platform/full principal, blank user, Suricata-only, or out-of-window: no incident.
- raw user-bearing events without linked detections cannot satisfy the identity rule.
- Windows case-only variants match; Linux case-only variants remain distinct; down-level, UPN, and bare principals do not merge.
- cross-host within one platform is intentional and tested.

## Gate 7 — page-boundary and backlog tests

### 1,001 same-timestamp reproduction

Use a 1,000-input candidate batch and run all three persisted correlation-input shapes at one UTC millisecond:

1. 1,001 unique detection inputs under an isolated nonmatching detection threshold.
2. 1,001 unique allowlisted event inputs under an approved mixed rule whose required detection condition is deliberately absent, proving event-context ledgering without event-only incident creation.
3. A mixed detection/event union totaling 1,001, including at least one identical textual input ID in both kinds to prove `(input_kind, input_id)` namespace separation.

For each run:

- collapse physical source duplicates before the batch limit;
- first run uninterrupted and require page two to begin within one second of page-one completion, with all 1,001 identities complete within 15 seconds;
- repeat from an isolated equivalent scope, stop immediately after exactly 1,000 complete ledger keys and persisted rule/episode/schedule state, and retain volumes;
- restart the same engine/rule ID/version/fingerprint and require the remainder within one second after the engine reports ready/enters its processing loop and within 15 seconds of that readiness point;
- for both variants, assert exact equality to all 1,001 expected `(engine, rule ID, version, fingerprint, input kind, input ID)` keys, zero independent anti-join backlog, null oldest-input timestamp, zero oldest-input age, zero logical incidents, and zero detection/event links; and
- add a late-visible lower lexical identity after restart, prove bounded rotation plus the ledger—not the stale cursor—finds it exactly once, then repeat the zero-backlog, null-oldest-timestamp, and zero-oldest-age assertions.

### 10K backlog

- Preload 10,000 bounded nonmatching eligible correlation inputs under one isolated rule scope, or construct and assert the full expected input/rule-scope identity set when multiple rules are active.
- Require exact expected evaluation-identity equality, `unevaluated_input_count = 0`, `oldest_unevaluated_observed_at IS NULL`, `oldest_unevaluated_age_seconds = 0.0`, zero logical incidents, zero detection/event links, healthy services, and the frozen <=60-second drain target.
- Capture per-cycle work, query duration/bytes, CPU/RAM, and all error/drop/retry counters.

## Gate 8 — sustained and coexistence performance

Run in an isolated Compose project with fresh v0.6 volumes; do not delete existing benchmark volumes.

1. Five minutes at 100 eligible correlation inputs/second; release gate. After sender completion it must reach exact ledger equality, final backlog zero, null oldest-input timestamp, and oldest-input age zero within 30 seconds.
2. Characterize 250 and then 500 eligible correlation inputs/second only while healthy.
3. Run an immediately preceding same-code v0.5.2 100K source-event control with correlation disabled/idle, then repeat with correlation active.
4. Repeat the v0.5.2 sustained 500 source-EPS control the same way.

Record accepted/input/ledger counts, incidents/links, send rate, ClickHouse completion, correlation completion, final backlog and oldest-input timestamp/age, incident latency, query cost, CPU/RAM, container restarts, errors/rejections/drops, and logical/physical duplicate counts. Every successful drain, including characterized 250/500 runs, must finish at backlog zero and oldest age zero even when its drain time is not a release SLO. Do not fabricate unavailable Vector metrics or classify different-host measurements as regressions.

## Gate 9 — controlled real-lab acceptance

Real evidence must use empty synthetic `validation_id` markers and be recorded separately from fixtures.

### Linux sequence

- Isolated owned Linux VM and source only.
- Disposable account capable of one legitimate final login.
- Exactly five deliberate failed authentications, no wordlist/repeated guessing loop, followed by one correct login within five minutes.
- Verify five real failure detections, one real normalized success event, one incident, IDs, timeline, severity, MITRE, and restart deduplication.
- Remove temporary credentials/configuration afterward.

### Windows host correlation

- Generate two different harmless real Windows activities that trigger two existing medium/high rules on the same endpoint within ten minutes.
- Verify two distinct real detections and exactly one host incident with the expected stable identity and evidence.
- Do not introduce arbitrary attack payloads or weaken detection rules for the test.

### Suricata plus endpoint

- Isolated lab only.
- Use controlled local SID `9000001` and signature beginning `FUSION TEST`; do not modify a community rule.
- Generate harmless network traffic involving IP X, a real endpoint detection, and a real direction-safe normalized endpoint network record that proves the canonical IP was locally owned by that canonical host during the same occurrence window.
- Verify one incident for network-first, endpoint-first, and ownership-context-last visibility orders, IPv4-mapped IPv6 equivalence, multi-IP preservation, cross-source evidence, all IDs, and timeline.
- Prove that simple hostname/IP equality, stale ownership, and a reused IP owned by another host do not qualify.
- Validate Suricata configuration before restart and remove the temporary rule afterward.

## Gate 10 — Grafana

Provision one `Fusion Incidents` dashboard with a 24-hour default and 15-30 second refresh. Required variables:

`status`, `severity`, `incident_type`, `host`, `user`, `correlation_rule`, `tactic`, `technique`, `cross_source`, and selected `incident_id`.

Required panels:

- open incidents (`new` + `acknowledged`);
- new incidents;
- high/critical open incidents;
- open cross-source incidents;
- persisted correlation backlog and oldest age;
- incidents over time by severity;
- severity and incident-type distribution;
- affected hosts and users;
- MITRE techniques;
- cross-source incident table;
- current incident table; and
- selected incident detail plus deterministic timeline.

Summary time uses `created_at`; the current incident table is explicitly filtered/labeled by `last_seen`. Do not mix time semantics silently. Timeline shows occurrence and visibility/detection time so lateness is visible.

Validation must prove:

- JSON/schema and datasource UID;
- every required variable/panel/query;
- every query executes against seeded data with exact expected filter counts;
- only current logical incident/link rows appear;
- the incident data link selects the exact ID;
- every evidence link appears once in deterministic order;
- no raw JSON/credential appears; and
- Grafana API provisioning plus a manual visual check shows no panel errors.

Grafana reads compact persisted `fusion.correlation_schedule_state` telemetry for backlog panels; it must not run live full-ledger anti-joins on each refresh. A drained scope must display backlog `0` and oldest age `0`, not stale values or “no data.”

## Gate 11 — full regression and release sequence

Required before a PR is considered ready:

- correlation unit/security/rule tests;
- PowerShell syntax and compatibility checks;
- Bash syntax and ShellCheck where relevant;
- future Vector config and existing 27 Vector tests unchanged/green;
- existing Suricata config/tests green;
- all nine current Sigma rules unchanged/green;
- fresh and upgrade migration validation;
- correlation restart/replay/crash/late tests;
- exact 1,001 and 10K tests;
- controlled real Linux, Windows, and Suricata/endpoint evidence;
- Grafana automated and visual validation;
- full existing Fusion validation;
- Compose config and all services healthy;
- `git diff --check`; and
- only intentional files committed on a feature branch.

Release order:

1. Push feature branch and open reviewed PR.
2. Require all PR checks green; do not merge on failure.
3. Merge only after design/implementation/security review approval.
4. Require the same validation green on `main`.
5. Verify the release commit from a fresh clone/isolated project.
6. Record all manual real and performance evidence.
7. Only then create the annotated `v0.6.0` tag and GitHub Release.

## Required acceptance report

The final implementation report must include:

- exact commits and files changed;
- final frozen architecture decisions;
- table/rule versions and fingerprints;
- all commands/tests and PASS/FAIL/SKIPPED counts;
- migration provenance;
- synthetic and real evidence clearly separated;
- exact logical source/ledger/incident/link counts;
- before/after and coexistence performance results;
- CPU/RAM/query-cost observations;
- errors, retries, drops, restarts, and duplicate findings;
- any manual steps or skipped gates; and
- an explicit statement that no release tag exists unless every gate passed.

## Explicitly out of scope

- SOAR and automated remediation
- email, Slack, or other notifications
- AI/LLM summaries
- comments, assignment, ticketing, and analyst case-management UI/API
- multi-tenancy and RBAC
- HA/distributed correlation
- external threat-intelligence enrichment
- asset inventory, NAT/DHCP identity resolution, and universal principal resolution
- unlimited historical backfill
- enterprise capacity claims

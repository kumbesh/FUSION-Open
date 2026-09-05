# Fusion v0.5 repeatable detection demo

This workflow demonstrates the released Fusion v0.5 detection path with safe,
real lab telemetry. It generates one harmless Windows process event, optionally
one failed Linux SSH authentication, and optionally one controlled Suricata
alert. It does not install software, change Fusion rules, alter migrations, or
delete Docker data.

```text
Windows Sysmon ─┐
Linux journald ─┼─> Vector ─> ClickHouse ─> Fusion Detection Engine ─> Grafana
Suricata EVE ───┘                              │
                                              └─> Sigma + MITRE ATT&CK
```

## Safety boundary

Run this only in an isolated lab that you own or are authorized to test. The
script accepts only literal RFC1918, loopback, or link-local IPv4 addresses for
SSH and ICMP targets. It does not generate an exploit, scan a
network, guess passwords, install dependencies, alter firewall policy, restart
Suricata, or destroy Docker volumes.

The Linux step makes exactly one login attempt for the fixed nonexistent user
`definitely-not-a-user`. You enter one intentionally incorrect lab-only
password. Do not reuse a real password.

The Suricata step uses private SID `9000001` and the exact temporary rule shown
below. Never place this rule on an Internet-facing or production sensor. Never
edit or replace a Suricata community rule to run this demo.

## Prerequisites

The Windows computer from which the script runs needs:

- PowerShell 5.1 or later.
- Docker Desktop with Docker Compose v2.
- A running Fusion v0.5 stack with healthy `clickhouse`, `vector`,
  `fusion-detection-engine`, and `grafana` services.
- Sysmon installed and running with Process Creation (Event ID 1) enabled.
- The `Microsoft-Windows-Sysmon/Operational` channel enabled.
- `FusionVectorAgent` running and configured for the active Fusion collector.

For the optional Linux step, the Windows host also needs OpenSSH Client and TCP
22 access to an isolated Linux endpoint. That endpoint needs sshd, journald, and
the Fusion Linux agent running. Its lab-only sshd configuration must permit one
password-authentication request so the normalized `Failed password for invalid
user` event is produced. Do not weaken a production SSH server for this demo.
If these prerequisites are absent, the script prints `SKIPPED` and continues.

For the optional Suricata step, the Windows host needs key-based SSH access to
the isolated Suricata sensor. The sensor needs `ping`, active `suricata`, and
active `fusion-suricata-vector` services. Its EVE output and Fusion agent must
already be configured. If these prerequisites are absent, the script prints
`SKIPPED` and continues.

If an endpoint is a separate VM, the Fusion receiver must already be bound to a
private interface reachable by that VM, with TCP 8686 allowed only from the VM
or isolated lab subnet. Fusion v0.5 HTTP ingestion has no TLS or authentication;
never expose it to the public Internet.

## Preflight without generating controlled detection events

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo-v05.ps1 -PreflightOnly
```

Add an optional Linux target to check TCP reachability without attempting a
login or sending ICMP:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo-v05.ps1 `
  -PreflightOnly `
  -LinuxTarget 192.168.186.129
```

Reachability checks open a TCP connection and may therefore appear as ordinary
network telemetry. `-PreflightOnly` does not launch encoded PowerShell, attempt
SSH authentication, establish a remote SSH session, or send the controlled ICMP
request.

## Prepare the temporary Suricata rule

Skip this section if you only want the Windows and Linux demonstrations. These
commands intentionally remain manual: the Fusion demo script never changes a
sensor's security configuration.

On the isolated Suricata sensor, run the guarded preparation block below. It:

1. Resolves the effective Suricata rule directory and restricts it to the
   standard `/etc` or `/var/lib` rule locations.
2. Refuses existing state, symbolic links, or an existing SID `9000001`.
3. Backs up `suricata.yaml` and any pre-existing `local.rules` in a root-only
   restoration directory.
4. Creates `local.rules` and adds it to `rule-files` only when required. It
   never edits `suricata.rules` or another community rule file.
5. Records hashes of the temporary configuration so cleanup cannot overwrite
   changes made concurrently.
6. Validates the complete configuration before a restart is possible.

```bash
sudo sh <<'FUSION_SURICATA_PREP'
set -eu

SURICATA_CONFIG=/etc/suricata/suricata.yaml
STATE_DIR=/etc/suricata/.fusion-v05-acceptance
RULE_TEXT='alert icmp any any -> any any (msg:"FUSION TEST v0.5 Controlled Acceptance"; sid:9000001; rev:1;)'
CONFIG_TEMP=
RULE_TEMP=

remove_temporary_files() {
  [ -z "$CONFIG_TEMP" ] || rm -f -- "$CONFIG_TEMP"
  [ -z "$RULE_TEMP" ] || rm -f -- "$RULE_TEMP"
}
remove_state_directory() {
  rm -f -- \
    "$STATE_DIR/suricata.yaml" \
    "$STATE_DIR/local.rules" \
    "$STATE_DIR/default-rule-path" \
    "$STATE_DIR/rule-existed" \
    "$STATE_DIR/rule-absent" \
    "$STATE_DIR/temporary-config.sha256" \
    "$STATE_DIR/temporary-rule.sha256"
  rmdir -- "$STATE_DIR"
}
trap remove_temporary_files EXIT HUP INT TERM

if [ ! -f "$SURICATA_CONFIG" ] || [ -L "$SURICATA_CONFIG" ]; then
  echo "ERROR: $SURICATA_CONFIG is not a trusted regular file." >&2
  exit 1
fi
if [ -e "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
  echo "ERROR: $STATE_DIR already exists; run or diagnose cleanup first." >&2
  exit 1
fi

config_dump=$(suricata --dump-config -c "$SURICATA_CONFIG")
default_rule_path=$(printf '%s\n' "$config_dump" | sed -n 's/^default-rule-path = //p')
case "$default_rule_path" in
  /etc/suricata/rules|/var/lib/suricata/rules) ;;
  *) echo "ERROR: unsupported or ambiguous default-rule-path: $default_rule_path" >&2; exit 1 ;;
esac
if [ ! -d "$default_rule_path" ] || [ -L "$default_rule_path" ]; then
  echo "ERROR: $default_rule_path is not a trusted rule directory." >&2
  exit 1
fi
RULE_FILE=$default_rule_path/local.rules
if [ -e "$RULE_FILE" ] && { [ ! -f "$RULE_FILE" ] || [ -L "$RULE_FILE" ]; }; then
  echo "ERROR: $RULE_FILE is not a trusted regular file." >&2
  exit 1
fi

local_rules_referenced=0
if printf '%s\n' "$config_dump" | grep -Eq '^rule-files\.[0-9]+ = local\.rules$'; then
  local_rules_referenced=1
fi
if [ "$local_rules_referenced" -eq 1 ] && [ ! -f "$RULE_FILE" ]; then
  echo "ERROR: effective config references missing $RULE_FILE." >&2
  exit 1
fi
if [ "$local_rules_referenced" -eq 0 ]; then
  rule_files_blocks=$(grep -Ec '^rule-files:[[:space:]]*$' "$SURICATA_CONFIG" || true)
  if [ "$rule_files_blocks" -ne 1 ]; then
    echo "ERROR: cannot safely add local.rules to the YAML rule-files block." >&2
    exit 1
  fi
fi

scanned_rule_directory=0
for rules_dir in /etc/suricata/rules /var/lib/suricata/rules; do
  [ -d "$rules_dir" ] || continue
  scanned_rule_directory=1
  set +e
  grep -R --line-number --fixed-strings 'sid:9000001;' "$rules_dir"
  grep_status=$?
  set -e
  case "$grep_status" in
    0) echo "ERROR: SID 9000001 already exists; do not modify it." >&2; exit 1 ;;
    1) ;;
    *) echo "ERROR: could not safely search $rules_dir." >&2; exit 1 ;;
  esac
done
if [ "$scanned_rule_directory" -ne 1 ]; then
  echo "ERROR: no Suricata rule directory was found." >&2
  exit 1
fi

install -d -o root -g root -m 0700 "$STATE_DIR"
cp -a -- "$SURICATA_CONFIG" "$STATE_DIR/suricata.yaml"
printf '%s\n' "$default_rule_path" > "$STATE_DIR/default-rule-path"

if [ -f "$RULE_FILE" ]; then
  cp -a -- "$RULE_FILE" "$STATE_DIR/local.rules"
  : > "$STATE_DIR/rule-existed"
else
  : > "$STATE_DIR/rule-absent"
fi

if [ "$local_rules_referenced" -eq 0 ]; then
  CONFIG_TEMP=$(mktemp /etc/suricata/.fusion-v05-config.XXXXXX)
  sed '/^rule-files:[[:space:]]*$/a\  - local.rules' \
    "$STATE_DIR/suricata.yaml" > "$CONFIG_TEMP"
  chown --reference="$STATE_DIR/suricata.yaml" "$CONFIG_TEMP"
  chmod --reference="$STATE_DIR/suricata.yaml" "$CONFIG_TEMP"
  mv -f -- "$CONFIG_TEMP" "$SURICATA_CONFIG"
  CONFIG_TEMP=
fi

if [ -f "$RULE_FILE" ]; then
  printf '\n%s\n' "$RULE_TEXT" >> "$RULE_FILE"
else
  RULE_TEMP=$(mktemp "$default_rule_path/.fusion-v05-rule.XXXXXX")
  printf '%s\n' "$RULE_TEXT" > "$RULE_TEMP"
  chown root:root "$RULE_TEMP"
  chmod 0644 "$RULE_TEMP"
  mv -f -- "$RULE_TEMP" "$RULE_FILE"
  RULE_TEMP=
fi

sha256sum "$SURICATA_CONFIG" | awk '{print $1}' > "$STATE_DIR/temporary-config.sha256"
sha256sum "$RULE_FILE" | awk '{print $1}' > "$STATE_DIR/temporary-rule.sha256"

if ! suricata -T -c "$SURICATA_CONFIG"; then
  cp -a -- "$STATE_DIR/suricata.yaml" "$SURICATA_CONFIG"
  if [ -f "$STATE_DIR/rule-existed" ]; then
    cp -a -- "$STATE_DIR/local.rules" "$RULE_FILE"
  else
    rm -f -- "$RULE_FILE"
  fi
  if suricata -T -c "$SURICATA_CONFIG"; then
    remove_state_directory
    echo "ERROR: temporary validation failed; original files were restored and state was removed." >&2
  else
    echo "ERROR: temporary and restored configurations failed validation; $STATE_DIR was retained." >&2
  fi
  exit 1
fi

systemctl restart suricata
systemctl is-active --quiet suricata
systemctl is-active --quiet fusion-suricata-vector
grep -qxF "$RULE_TEXT" "$RULE_FILE"
echo "Suricata acceptance SID 9000001 is loaded. Mandatory cleanup is still required."
FUSION_SURICATA_PREP
```

Because the block uses `set -eu` and an explicit validation guard, a failed
validation cannot fall through to the restart. Do not run the demo if this block
returns nonzero. If it leaves the state directory in place, diagnose the error
and use the mandatory cleanup below. Do not delete the state directory manually.

## Run the demo

Windows-only, using the current Compose project:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo-v05.ps1
```

Windows plus one controlled failed SSH authentication:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo-v05.ps1 `
  -LinuxTarget 192.168.186.129
```

All three demonstrations, after preparing SID `9000001` and replacing the
example ICMP peer with the private address that the Suricata sensor observes:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo-v05.ps1 `
  -LinuxTarget 192.168.186.129 `
  -SuricataSshTarget fusion@192.168.186.129 `
  -SuricataIcmpTarget 192.168.186.2 `
  -SuricataRuleReady
```

Use the sensor interface address that will source the ICMP packet in
`-SuricataSshTarget`; the script binds the one ping to that address so it can
correlate the exact source/destination pair in the resulting EVE alert.

The Windows command is generated internally as a unique, harmless
`Write-Output` expression and passed to `powershell.exe -EncodedCommand`. The
Linux SSH options disable public-key and keyboard-interactive authentication,
allow one password prompt, and make one connection attempt. The Suricata step
uses key-based noninteractive SSH to send one ICMP echo request from the sensor.

The script polls ClickHouse for new detections and prints:

- `rule_id`
- `severity`
- `platform`
- `host_name`
- `mitre_technique_ids`
- `source_event_uid`
- `detection_id`

It reads the ClickHouse username and password only inside the ClickHouse
container and does not print generated credentials. Any required failure causes
a nonzero exit. Missing optional Linux or Suricata prerequisites produce a clear
`SKIPPED` result without failing a successful Windows demonstration. Once an
optional test begins, failure to observe its telemetry or detection is a real
`FAIL` and causes a nonzero exit.

## Run against the isolated clean project

To leave a development stack untouched, run this script from the `main`
checkout while targeting the clean Compose project created from the released
tag:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\demo-v05.ps1 `
  -ComposeProjectName fusion-v050-clean `
  -LinuxTarget 192.168.186.129 `
  -SuricataSshTarget fusion@192.168.186.129 `
  -SuricataIcmpTarget 192.168.186.2 `
  -SuricataRuleReady
```

`-ComposeProjectName` is applied only for the lifetime of the script. If it is
omitted, the existing `COMPOSE_PROJECT_NAME` value or the Compose file's default
project is used. The command never invokes `docker compose down`, never passes
`-v`, and never changes the `v0.5.0` checkout or tag.

## Expected detections

| Demo | Expected rule | Severity | Platform | MITRE ATT&CK |
| --- | --- | --- | --- | --- |
| Harmless encoded PowerShell | `fusion-windows-encoded-powershell` | high | windows | T1059.001 |
| One failed SSH authentication | `fusion-linux-authentication-failure` | low | linux | T1110 |
| Controlled Suricata alert | `fusion-network-controlled-suricata-signature` | medium | network | Command and Control tactic; no technique ID |

For Suricata, the script first proves that a new EVE alert with SID `9000001`
and a signature beginning `FUSION TEST` reached `fusion.sysmon_events`. It then
requires a detection tied to that exact source event UID.

## Verify the EVE alert on the sensor

After the ICMP step, inspect the source directly before cleanup:

```bash
sudo grep --fixed-strings '"signature_id":9000001' /var/log/suricata/eve.json | tail -n 1
```

Depending on Suricata's JSON serialization, `signature_id` may appear as a
quoted string. If the fixed-string check returns nothing, inspect recent alert
records without changing them:

```bash
sudo tail -n 100 /var/log/suricata/eve.json | grep --fixed-strings 'FUSION TEST'
```

## Mandatory Suricata cleanup

Restore the exact pre-demo configuration and local-rule state with this guarded
block. It refuses cleanup if either temporary file changed after preparation and
retains the root-only restoration state unless validation, restart, SID-absence
verification, and shipper health all succeed:

```bash
sudo sh <<'FUSION_SURICATA_CLEANUP'
set -eu

SURICATA_CONFIG=/etc/suricata/suricata.yaml
STATE_DIR=/etc/suricata/.fusion-v05-acceptance

if [ ! -d "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
  echo "ERROR: trusted restoration state is unavailable." >&2
  exit 1
fi
if [ "$(stat -c '%U:%G:%a' "$STATE_DIR")" != "root:root:700" ]; then
  echo "ERROR: restoration-state ownership or mode is unsafe." >&2
  exit 1
fi
if [ ! -f "$STATE_DIR/suricata.yaml" ] || [ -L "$STATE_DIR/suricata.yaml" ]; then
  echo "ERROR: trusted configuration backup is unavailable." >&2
  exit 1
fi
if [ ! -f "$SURICATA_CONFIG" ] || [ -L "$SURICATA_CONFIG" ]; then
  echo "ERROR: current Suricata configuration is not a trusted regular file." >&2
  exit 1
fi
if [ ! -f "$STATE_DIR/default-rule-path" ] || [ -L "$STATE_DIR/default-rule-path" ]; then
  echo "ERROR: recorded rule path is unavailable." >&2
  exit 1
fi

default_rule_path=$(cat "$STATE_DIR/default-rule-path")
case "$default_rule_path" in
  /etc/suricata/rules|/var/lib/suricata/rules) ;;
  *) echo "ERROR: invalid recorded rule path." >&2; exit 1 ;;
esac
RULE_FILE=$default_rule_path/local.rules

if [ ! -f "$RULE_FILE" ] || [ -L "$RULE_FILE" ]; then
  echo "ERROR: expected temporary local.rules is unavailable." >&2
  exit 1
fi
if [ -f "$STATE_DIR/rule-existed" ] && [ ! -e "$STATE_DIR/rule-absent" ]; then
  if [ ! -f "$STATE_DIR/local.rules" ] || [ -L "$STATE_DIR/local.rules" ]; then
    echo "ERROR: trusted local.rules backup is unavailable." >&2
    exit 1
  fi
  rule_existed=1
elif [ -f "$STATE_DIR/rule-absent" ] && [ ! -e "$STATE_DIR/rule-existed" ]; then
  rule_existed=0
else
  echo "ERROR: ambiguous original local.rules state." >&2
  exit 1
fi

for hash_file in temporary-config.sha256 temporary-rule.sha256; do
  if [ ! -f "$STATE_DIR/$hash_file" ] || [ -L "$STATE_DIR/$hash_file" ] || \
     ! grep -Eq '^[0-9a-f]{64}$' "$STATE_DIR/$hash_file"; then
    echo "ERROR: invalid $hash_file restoration guard." >&2
    exit 1
  fi
done

expected_config_hash=$(cat "$STATE_DIR/temporary-config.sha256")
expected_rule_hash=$(cat "$STATE_DIR/temporary-rule.sha256")
actual_config_hash=$(sha256sum "$SURICATA_CONFIG" | awk '{print $1}')
actual_rule_hash=$(sha256sum "$RULE_FILE" | awk '{print $1}')
if [ "$actual_config_hash" != "$expected_config_hash" ] || \
   [ "$actual_rule_hash" != "$expected_rule_hash" ]; then
  echo "ERROR: Suricata files changed after preparation; refusing to overwrite them." >&2
  exit 1
fi

cp -a -- "$STATE_DIR/suricata.yaml" "$SURICATA_CONFIG"
if [ "$rule_existed" -eq 1 ]; then
  cp -a -- "$STATE_DIR/local.rules" "$RULE_FILE"
else
  rm -f -- "$RULE_FILE"
fi

suricata -T -c "$SURICATA_CONFIG"
systemctl restart suricata
systemctl is-active --quiet suricata

scanned_rule_directory=0
for rules_dir in /etc/suricata/rules /var/lib/suricata/rules; do
  [ -d "$rules_dir" ] || continue
  scanned_rule_directory=1
  set +e
  grep -R --line-number --fixed-strings 'sid:9000001;' "$rules_dir"
  grep_status=$?
  set -e
  case "$grep_status" in
    0) echo "ERROR: SID 9000001 remains after restoration." >&2; exit 1 ;;
    1) ;;
    *) echo "ERROR: could not safely search $rules_dir." >&2; exit 1 ;;
  esac
done
if [ "$scanned_rule_directory" -ne 1 ]; then
  echo "ERROR: no Suricata rule directory was found." >&2
  exit 1
fi

systemctl is-active --quiet fusion-suricata-vector
rm -f -- \
  "$STATE_DIR/suricata.yaml" \
  "$STATE_DIR/local.rules" \
  "$STATE_DIR/default-rule-path" \
  "$STATE_DIR/rule-existed" \
  "$STATE_DIR/rule-absent" \
  "$STATE_DIR/temporary-config.sha256" \
  "$STATE_DIR/temporary-rule.sha256"
rmdir -- "$STATE_DIR"
echo "Temporary SID 9000001 was removed, original files restored, and Suricata is healthy."
FUSION_SURICATA_CLEANUP
```

If any command fails, the shell stops and leaves the restoration state in place.
Diagnose the failure and rerun cleanup; do not delete the state directory
manually while the temporary rule may still be active.

## Troubleshooting

- **Fusion services fail preflight:** run `docker compose ps` with the same
  Compose project name. All four services must report `running` and `healthy`.
  Inspect a failing service with `docker compose logs --tail 100 <service>`.
- **Windows prerequisite fails:** run `Get-Service Sysmon,FusionVectorAgent` and
  `Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational`. Confirm the
  Sysmon configuration includes Event ID 1 and that new Process Creation events
  appear in Event Viewer.
- **Windows event exists but no detection appears:** check the Vector endpoint
  configured by `agents/windows/configure.ps1`. When using an isolated Compose
  project, confirm its published receiver with `docker compose -p
  fusion-v050-clean port vector 8686` and ensure the agent targets that same
  reachable address. Then inspect `docker compose logs --tail 100
  fusion-detection-engine`.
- **Linux step is skipped:** confirm TCP 22 is reachable, sshd is active, the
  Fusion Linux agent is running, and failed sshd messages reach journald. The
  script intentionally does not install or start any of them.
- **Linux attempt produces no normalized failure:** confirm the isolated sshd
  permits password authentication for this one controlled request. Do not
  weaken a production SSH server for the demo.
- **Linux login fails but no detection appears:** verify that the normalized row
  has `source_type=linux_journald`, `event_category=authentication`,
  `outcome=failure`, and `user_name=definitely-not-a-user`.
- **Suricata step is skipped:** configure key-based SSH for the lab account and
  confirm `suricata`, `fusion-suricata-vector`, and `ping` are available. The
  script never accepts or stores an SSH password for this step.
- **The server accepts a key but the demo still skips:** a passphrase-protected
  private key must already be unlocked in an SSH agent because the demo uses
  `BatchMode=yes`. Verify `ssh -o BatchMode=yes user@sensor true` succeeds before
  preparing the temporary rule; do not remove a production key's passphrase.
- **No Suricata EVE alert:** confirm the local rule is loaded, ICMP crosses the
  monitored interface, and `/var/log/suricata/eve.json` contains the `FUSION
  TEST` alert. Then check `journalctl -u fusion-suricata-vector`.
- **EVE alert exists but detection does not:** inspect
  `docker compose logs --tail 100 fusion-detection-engine` and confirm the
  stored event has `event_kind=alert`, `signature_id=9000001`, and a signature
  beginning `FUSION TEST`.

The historical real acceptance evidence for Fusion v0.5 is recorded separately
in [`detection-acceptance.md`](detection-acceptance.md).

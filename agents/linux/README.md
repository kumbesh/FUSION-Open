# Fusion Linux Vector agent

This directory contains the repository-managed Vector 0.58.0 agent initially targeting Ubuntu 24.04 LTS. The configuration and scripts are validated in CI on Ubuntu 24.04, and real endpoint acceptance was completed on an x86_64 Ubuntu 26.04 LTS VMware VM on 2026-09-03. It reads new records from `/var/log/audit/audit.log` and the native systemd journal, then sends one JSON event per request to the existing Fusion collector at `/linux`.

The agent does **not** install, enable, or configure auditd. It does not change journald, SSH, sudo, PAM, or system audit policy.

## Prerequisites

- Ubuntu 24.04 LTS on x86_64 or aarch64 as the configuration/CI target
- Ubuntu 26.04 LTS on x86_64 as a real-endpoint-tested VMware target
- systemd and `journalctl`
- auditd already installed and active
- `/var/log/audit/audit.log` present and readable by root
- TCP connectivity to the Fusion host's restricted port 8686 binding
- root access for installation and service management

Verify the endpoint before installing:

```sh
dpkg-query --show auditd
command -v auditctl
sudo systemctl is-active auditd.service
sudo auditctl -s
sudo test -r /var/log/audit/audit.log
sudo journalctl --verify
sudo ausearch -m EXECVE,SYSCALL,USER_CMD,USER_LOGIN,USER_AUTH,USER_ACCT,CRED_ACQ,CRED_DISP --start recent
sudo journalctl --boot --unit ssh.service --unit sshd.service --unit systemd-logind.service --lines 20
```

An empty `ausearch` result is not an agent error: auditd must already have rules and PAM auditing that produce the record types you intend to collect.

## Optional LAB/TEST audit examples

The following examples are for a disposable, isolated test VM only. Review the volume and privacy impact before using them. Fusion never applies these rules automatically.

Temporarily record 64-bit and 32-bit `execve` calls until the next reboot:

```sh
sudo auditctl -a always,exit -F arch=b64 -S execve -k fusion-lab-exec
sudo auditctl -a always,exit -F arch=b32 -S execve -k fusion-lab-exec
```

Remove those temporary LAB/TEST rules:

```sh
sudo auditctl -d always,exit -F arch=b64 -S execve -k fusion-lab-exec
sudo auditctl -d always,exit -F arch=b32 -S execve -k fusion-lab-exec
```

If you want persistent rules, use the auditd mechanism supported by your distribution and organization. Do not copy broad lab rules into production; command arguments may contain credentials or other sensitive data, and `execve` auditing can be high volume.

## Install and operate

Copy or clone the repository on the Linux endpoint. From this directory, use the Fusion host interface address reachable from the VM:

```sh
sudo ./install.sh http://<FUSION_HOST_LAB_IP>:8686/linux
./status.sh
```

The installer downloads the pinned official Vector 0.58.0 archive for the detected CPU architecture, verifies its SHA-256 digest, validates the rendered configuration, installs a hardened systemd unit, enables it at boot, and starts it. It refuses to proceed when auditd or the audit log prerequisite is missing.

Lifecycle commands:

```sh
sudo ./configure.sh http://<FUSION_HOST_LAB_IP>:8686/linux
sudo ./start.sh
sudo ./stop.sh
./status.sh
sudo ./uninstall.sh
```

`uninstall.sh` preserves checkpoints, the disk buffer, and local Vector logs. Use `sudo ./uninstall.sh --purge-data` only when those exact Fusion agent directories should also be permanently deleted. Neither form modifies auditd or journald.

Validate the template with a local Vector 0.58.0 binary without installing the service:

```sh
./test-config.sh /path/to/vector
```

Installed locations:

| Purpose | Location |
| --- | --- |
| Vector binary | `/usr/local/lib/fusion-vector-agent/bin/vector` |
| Rendered configuration | `/etc/fusion-vector-agent/vector.yaml` |
| Install metadata | `/etc/fusion-vector-agent/install.env` |
| Checkpoints and disk buffer | `/var/lib/fusion-vector-agent` |
| Local Vector logs | `/var/log/fusion-vector-agent` |
| systemd unit | `/etc/systemd/system/fusion-vector-agent.service` |

The service runs as root because the audit log is normally restricted. Its systemd sandbox denies privilege escalation, limits capabilities to audit-log traversal, protects the host filesystem, and permits writes only to the dedicated state and log directories.

## Generate and verify lab telemetry

After the agent starts, generate harmless activity:

```sh
/usr/bin/printf 'fusion-linux-test\n'
sudo /usr/bin/id
sudo systemd-run --unit=fusion-lab-test --collect /usr/bin/true
```

From a second machine on the isolated lab network, an SSH success or failed login can exercise the SSH authentication panels. Do not intentionally lock out an account and do not use real credentials in a shared lab.

Inspect source and agent logs:

```sh
sudo ausearch -m EXECVE,SYSCALL,USER_CMD --start recent -i
sudo journalctl --boot --identifier sshd --identifier sudo --lines 50
sudo journalctl --unit fusion-vector-agent.service --since '10 minutes ago'
sudo tail -n 50 /var/log/fusion-vector-agent/vector-*.log
```

On the Fusion host, query the normalized rows:

```sh
set -a
. ./.env
set +a
docker compose exec clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT event_time, host_name, source_type, event_action, process_path, user_name, outcome FROM fusion.sysmon_events WHERE platform = 'linux' ORDER BY event_time DESC LIMIT 25"
```

## Troubleshooting and security

- `HTTP method not allowed` in a browser is expected: the receiver accepts `POST`, not `GET`.
- If the service is inactive, run `sudo journalctl -u fusion-vector-agent.service -n 100 --no-pager`.
- If audit events are absent, confirm auditd rules produce the requested record types. The agent begins at the end of the audit log and journal on first start.
- If journal events are absent, use `journalctl -o json` to verify the `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, or `_COMM` fields match the configured SSH, sudo, su, systemd, and logind filters.
- If delivery fails, test TCP 8686 from the VM and check the Fusion host firewall source restriction and `FUSION_BIND_ADDRESS`.

Fusion v0.3 ingestion has no TLS or authentication. Never expose TCP 8686 to the public Internet or an untrusted network. Bind it only to the specific isolated lab interface and permit only the endpoint VM address or lab subnet in the host firewall.

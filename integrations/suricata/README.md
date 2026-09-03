# Suricata EVE integration

This integration tails an existing Suricata EVE JSON file with Vector 0.58.0 and sends each complete EVE object to Fusion's shared `POST /security` endpoint. It does not install, start, stop, reconfigure, or upgrade Suricata.

## Prerequisites

- Linux x86_64 or aarch64 with systemd
- Suricata already installed and managed independently
- Newline-delimited EVE JSON at `/var/log/suricata/eve.json`, or another absolute path
- `alert`, `dns`, `http`, `tls`, and/or `flow` enabled in the sensor's EVE output
- A route to Fusion TCP 8686 on an isolated, firewall-restricted lab network
- Root access for installation and reading the protected EVE file

Verify without changing the sensor:

```sh
sudo systemctl is-active suricata.service
sudo test -r /var/log/suricata/eve.json
sudo tail -n 5 /var/log/suricata/eve.json
sudo grep -m 1 -E '"event_type":"(alert|dns|http|tls|flow)"' /var/log/suricata/eve.json
```

A service named differently from `suricata.service` is acceptable if EVE JSON is actively written. Do not loosen global file permissions; the Fusion shipper runs as root with only `CAP_DAC_READ_SEARCH`, a read-only `/var/log/suricata`, and a strict systemd sandbox.

## Install and manage

On the Fusion host, bind HTTP ingestion to a specific lab interface and permit TCP 8686 only from the sensor. On the sensor:

```sh
nc -vz <FUSION_HOST_LAB_IP> 8686
cd integrations/suricata
sudo sh ./install.sh http://<FUSION_HOST_LAB_IP>:8686/security /var/log/suricata/eve.json <SENSOR_NAME>
sh ./status.sh
```

The collector URL must use the literal Fusion host IP reachable by the sensor, not a hostname. The installer uses that IP and port to exclude the shipper's own collector connection from its EVE input, preventing recursive self-observation when Suricata monitors the outbound interface. It then downloads the pinned official Vector 0.58.0 archive for the detected architecture, verifies its SHA-256 digest, validates the rendered configuration, installs a hardened `fusion-suricata-vector.service`, enables it at boot, and starts it. Use `--no-start` to install without starting or `--force` to replace an existing Fusion integration installation.

```sh
sudo sh ./configure.sh http://<FUSION_HOST_LAB_IP>:8686/security /var/log/suricata/eve.json <SENSOR_NAME>
sudo sh ./start.sh
sudo sh ./stop.sh
sh ./status.sh
sudo sh ./uninstall.sh
sudo sh ./uninstall.sh --purge-data
```

Uninstall never changes Suricata or `eve.json`. Without `--purge-data`, it retains checkpoints, buffered events, and local logs.

## Paths and delivery behavior

| Purpose | Path |
| --- | --- |
| Vector binary | `/usr/local/lib/fusion-suricata-vector/bin/vector` |
| Rendered configuration | `/etc/fusion-suricata-vector/vector.yaml` |
| Installation metadata | `/etc/fusion-suricata-vector/install.env` |
| Checkpoints and disk buffer | `/var/lib/fusion-suricata-vector` |
| Local Vector logs | `/var/log/fusion-suricata-vector` |
| systemd unit | `/etc/systemd/system/fusion-suricata-vector.service` |

The source starts at the end of the file on first use, so installing it does not replay the complete EVE history. Vector checkpoints offsets and follows ordinary rename/create log rotation. Each source line is capped at 1 MiB. The HTTP sink sends one event per request, uses a bounded 256 MiB disk buffer, retries transient collector failures, and blocks when the buffer is full. This avoids unbounded memory or disk usage. Do not delete the data directory while delivery or replay matters.

HTTP 8686 currently has no TLS or authentication. Event bodies and metadata are visible in transit, and anyone who can reach the port can submit data. Use only an isolated lab network and a firewall rule limited to the sensor IP; never expose it to the public Internet.

## Verify storage

Generate ordinary, authorized traffic only inside the test lab. DNS plus HTTP/HTTPS traffic normally produces DNS, HTTP, TLS, and flow records:

```sh
dig example.com
curl --max-time 10 http://example.com/
curl --max-time 10 https://example.com/
sudo tail -n 20 /var/log/suricata/eve.json
```

An alert depends on the sensor's enabled rules. For isolated acceptance, an administrator may temporarily add an explicitly labeled local LAB/TEST rule such as `alert icmp any any -> any any (msg:"FUSION LAB ICMP TEST"; sid:1000001; rev:1;)`, verify the Suricata configuration with `suricata -T`, reload it using the site's normal procedure, and ping an authorized lab peer. Remove the rule after acceptance. Fusion never applies or reloads this rule.

Then run on the Fusion host:

```sh
set -a; . ./.env; set +a
docker compose exec clickhouse clickhouse-client \
  --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" \
  --query "SELECT event_time, device_name, event_action, signature_id, signature, domain, url, source_ip, destination_ip, length(raw_json) FROM fusion.sysmon_events WHERE product = 'Suricata' ORDER BY event_time DESC LIMIT 25"
```

Check that:

- `alert` becomes `event_kind=alert` and `event_action=network_alert` with signature fields.
- DNS queries populate `domain` and `query_name`.
- HTTP events populate `domain` and `url`.
- TLS events populate `domain` from SNI.
- Flow records retain network endpoints and `flow_id` in `source_event_id`.
- `raw_json` contains the full wrapped EVE object and source-file metadata.
- `source_address` contains the HTTP transport peer and is not substituted for the EVE `source_ip`.

Open **Fusion Security Sources** in Grafana and select Product `Suricata`.

## Real-sensor acceptance gate

The files in `samples/security-tools/` and the VRL tests are synthetic. They validate parsing but are not proof of a real sensor. Before tagging v0.4.0, record evidence that a real Suricata installation:

1. Is running and actively writing readable EVE JSON.
2. Connects to the intended Fusion lab interface through a source-restricted firewall rule.
3. Delivers real EVE events through the installed shipper and `/security`.
4. Stores at least the available real `alert`, `dns`, `http`, `tls`, and `flow` types correctly; any type not produced must be documented and tested before release.
5. Preserves complete raw EVE JSON and correct transport metadata.
6. Produces non-empty, accurate Suricata, DNS, HTTP, signature, and network queries in Grafana.
7. Leaves existing real Windows and Linux telemetry operational.

Until this checklist is complete, v0.4 is development work and must not be tagged or announced as complete.

The checklist was completed on a real Ubuntu 26.04 VMware sensor running Suricata 8.0.3 on 2026-09-03 UTC. The evidence, including the collector feedback-loop correction and regression tests, is recorded in [`docs/suricata-acceptance.md`](../../docs/suricata-acceptance.md). This does not replace the final full-suite and CI release gates.

## Troubleshooting

```sh
sh ./status.sh
sudo journalctl -u fusion-suricata-vector.service -n 100 --no-pager
sudo /usr/local/lib/fusion-suricata-vector/bin/vector validate \
  --no-environment --skip-healthchecks \
  --config-yaml /etc/fusion-suricata-vector/vector.yaml
```

- No new records: confirm EVE is growing after installation; the source intentionally starts at the end.
- Permission error: keep the service as installed and inspect directory traversal permissions/AppArmor; do not make EVE world-readable.
- HTTP errors: check the Fusion bind address, source-scoped firewall rule, route, collector health, and `docker compose logs vector`.
- Buffer growth: restore ClickHouse/collector availability before the bounded buffer fills. Stopping the integration preserves buffered data.
- Rotated file not followed: confirm Suricata renames and recreates the configured path normally and that its parent directory remains `/var/log/suricata`.

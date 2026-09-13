import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_PATH = ROOT / "grafana" / "dashboards" / "fusion-incidents.json"
PROVISIONING_PATH = (
    ROOT / "grafana" / "provisioning" / "dashboards" / "dashboards.yaml"
)
DATASOURCE_UID = "fusion-clickhouse"


def load_dashboard() -> dict:
    return json.loads(DASHBOARD_PATH.read_text(encoding="utf-8"))


def panel_by_title(dashboard: dict, title: str) -> dict:
    return next(panel for panel in dashboard["panels"] if panel["title"] == title)


def panel_sql(panel: dict) -> str:
    targets = panel.get("targets", [])
    assert len(targets) == 1
    return targets[0]["rawSql"]


def test_dashboard_contract_and_provisioning() -> None:
    dashboard = load_dashboard()

    assert dashboard["title"] == "Fusion Incidents"
    assert dashboard["uid"] == "fusion-incidents"
    assert dashboard["editable"] is False
    assert dashboard["time"] == {"from": "now-24h", "to": "now"}
    assert dashboard["refresh"] in {"15s", "20s", "30s"}
    assert len({panel["id"] for panel in dashboard["panels"]}) == len(
        dashboard["panels"]
    )

    required_variables = {
        "status",
        "severity",
        "incident_type",
        "host",
        "user",
        "correlation_rule",
        "tactic",
        "technique",
        "cross_source",
        "incident_id",
    }
    assert {item["name"] for item in dashboard["templating"]["list"]} == (
        required_variables
    )

    required_panels = {
        "Open incidents",
        "New incidents",
        "High/critical open incidents",
        "Open cross-source incidents",
        "Correlation backlog",
        "Oldest unevaluated input age",
        "Incidents created over time",
        "Incident severity distribution",
        "Incident type distribution",
        "Affected hosts",
        "Affected users",
        "MITRE techniques",
        "Cross-source incidents",
        "Current incidents (filtered by last seen)",
        "Selected incident detail",
        "Selected incident evidence timeline",
    }
    assert required_panels <= {panel["title"] for panel in dashboard["panels"]}

    provisioning = PROVISIONING_PATH.read_text(encoding="utf-8")
    assert "path: /var/lib/grafana/dashboards" in provisioning
    assert "allowUiUpdates: false" in provisioning


def test_queries_are_read_only_and_use_confirmation_aware_models() -> None:
    dashboard = load_dashboard()
    mutation = re.compile(
        r"\b(insert|alter|update|delete|truncate|drop|optimize|create|rename)\b",
        re.IGNORECASE,
    )

    for panel in dashboard["panels"]:
        assert panel["datasource"]["uid"] == DATASOURCE_UID
        for target in panel.get("targets", []):
            assert target["queryType"] == "sql"
            assert not mutation.search(target["rawSql"]), panel["title"]

    for variable in dashboard["templating"]["list"]:
        if variable["type"] != "query":
            continue
        assert variable["datasource"]["uid"] == DATASOURCE_UID
        assert variable["query"].lstrip().upper().startswith("SELECT ")
        assert not mutation.search(variable["query"]), variable["name"]

    all_sql = "\n".join(panel_sql(panel) for panel in dashboard["panels"])
    lowered = all_sql.lower()
    assert "fusion.incidents_current" in lowered
    assert "fusion.incident_timeline" in lowered
    assert "fusion.incident_detection_links " not in lowered
    assert "fusion.incident_event_links " not in lowered
    assert "from fusion.incidents " not in lowered
    assert "${cross_source:raw}" not in all_sql
    assert "${incident_id:raw}" not in all_sql
    assert "${cross_source:sqlstring}" in all_sql
    assert "${incident_id:sqlstring}" in all_sql
    assert ":regex}" not in all_sql

    for unsafe_field in (
        "raw_json",
        "evidence_json",
        "command_line",
        "password",
        "credential",
    ):
        assert unsafe_field not in lowered

    incident_queries = [
        panel_sql(panel)
        for panel in dashboard["panels"]
        if "fusion.incidents_current" in panel_sql(panel)
        and panel["title"] not in {"Selected incident detail"}
    ]
    for sql in incident_queries:
        if "mitre_tactic_ids" in sql:
            assert "has([${tactic:sqlstring}], '.*') OR arrayExists" in sql
        if "mitre_technique_ids" in sql:
            assert "has([${technique:sqlstring}], '.*') OR arrayExists" in sql


def test_time_semantics_backlog_and_deterministic_timeline() -> None:
    dashboard = load_dashboard()

    created_sql = panel_sql(panel_by_title(dashboard, "Incidents created over time"))
    assert "$__timeFilter(created_at)" in created_sql
    assert "$__timeInterval(created_at)" in created_sql
    assert "$__timeFilter(last_seen)" not in created_sql

    current_sql = panel_sql(
        panel_by_title(dashboard, "Current incidents (filtered by last seen)")
    )
    assert "$__timeFilter(last_seen)" in current_sql
    assert "FROM fusion.incidents_current" in current_sql

    backlog_sql = panel_sql(panel_by_title(dashboard, "Correlation backlog"))
    age_sql = panel_sql(
        panel_by_title(dashboard, "Oldest unevaluated input age")
    )
    for sql in (backlog_sql, age_sql):
        assert "fusion.correlation_schedule_state_current" in sql
        assert "correlation_evaluated_inputs" not in sql
        assert "sysmon_events" not in sql
        assert "fusion.detections" not in sql
    assert "ifNull(sum(unevaluated_input_count), 0)" in backlog_sql
    assert "ifNull(max(oldest_unevaluated_age_seconds), 0.0)" in age_sql

    timeline_sql = panel_sql(
        panel_by_title(dashboard, "Selected incident evidence timeline")
    )
    assert "FROM fusion.incident_timeline" in timeline_sql
    assert "WHERE ${incident_id:sqlstring} != '.*'" in timeline_sql
    assert "incident_id = ${incident_id:sqlstring}" in timeline_sql
    assert "ORDER BY occurred_at, input_kind, input_id" in timeline_sql
    assert "occurred_at AS Occurred" in timeline_sql
    assert "observed_at AS Observed" in timeline_sql
    assert "if(input_kind = 'detection', rule_name, event_action) AS RuleOrAction" in (
        timeline_sql
    )


def test_incident_table_link_selects_the_exact_incident_id() -> None:
    dashboard = load_dashboard()
    panel = panel_by_title(dashboard, "Current incidents (filtered by last seen)")
    overrides = panel["fieldConfig"]["overrides"]
    incident_override = next(
        item
        for item in overrides
        if item["matcher"] == {"id": "byName", "options": "IncidentID"}
    )
    links = next(
        item["value"]
        for item in incident_override["properties"]
        if item["id"] == "links"
    )
    assert len(links) == 1
    assert links[0]["url"].endswith(
        "&var-incident_id=${__data.fields.IncidentID}"
    )

    detail_sql = panel_sql(panel_by_title(dashboard, "Selected incident detail"))
    assert "WHERE ${incident_id:sqlstring} != '.*'" in detail_sql
    assert "incident_id = ${incident_id:sqlstring}" in detail_sql

    incident_variable = next(
        item
        for item in dashboard["templating"]["list"]
        if item["name"] == "incident_id"
    )
    assert "SELECT incident_id FROM fusion.incidents_current" in incident_variable[
        "query"
    ]


def test_cross_source_filter_has_only_bounded_values() -> None:
    dashboard = load_dashboard()
    variable = next(
        item
        for item in dashboard["templating"]["list"]
        if item["name"] == "cross_source"
    )
    assert variable["type"] == "custom"
    assert variable["multi"] is False
    assert {item["value"] for item in variable["options"]} == {
        "all",
        "yes",
        "no",
    }


def test_query_variable_all_values_render_as_valid_sql_literals() -> None:
    """Grafana emits a custom allValue verbatim, even with :sqlstring."""

    dashboard = load_dashboard()
    query_variables = {
        item["name"]: item
        for item in dashboard["templating"]["list"]
        if item["type"] == "query"
    }

    for variable in query_variables.values():
        assert variable["includeAll"] is True
        assert variable["allValue"] == "'.*'"

    rendered_sql = "\n".join(
        panel_sql(panel) for panel in dashboard["panels"]
    )
    for name, variable in query_variables.items():
        rendered_sql = rendered_sql.replace(
            "${" + name + ":sqlstring}", variable["allValue"]
        )

    assert "[.*]" not in rendered_sql
    assert "['.*']" in rendered_sql
    assert "WHERE '.*' != '.*'" in rendered_sql

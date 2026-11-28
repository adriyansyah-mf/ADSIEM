"""Case relation graph: entities per alert and the step-by-step endpoint."""
from app.services.case_graph import alert_entities

SHA = "9f2c" + "0" * 56 + "a41e"


def test_sysmon_process_event_names_user_process_parent_and_hash():
    found = alert_entities({
        "winlog.event_data.User": "JIMBE\\analyst", "Image": "C:\\Users\\Public\\beacon.exe",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe", "Hashes": f"MD5=abc,SHA256={SHA.upper()}",
    }, "JIMBE", None)
    assert found.entities == [
        ("host", "JIMBE"), ("user", "JIMBE\\analyst"), ("process", "C:\\Windows\\System32\\cmd.exe"),
        ("process", "C:\\Users\\Public\\beacon.exe"), ("hash", SHA)]
    assert ("process:C:\\Windows\\System32\\cmd.exe", "process:C:\\Users\\Public\\beacon.exe") in found.edges
    assert ("hash:" + SHA, "process:C:\\Users\\Public\\beacon.exe") in found.edges
    assert ("host:JIMBE", "process:C:\\Windows\\System32\\cmd.exe") in found.edges


def test_network_event_links_process_to_destination_and_skips_service_accounts():
    found = alert_entities({"process.executable": "beacon.exe", "destination.ip": "203.0.113.9",
                            "source.ip": "127.0.0.1", "user.name": "SYSTEM"}, "JIMBE", "10.0.0.5")
    assert ("ip", "203.0.113.9") in found.entities
    assert not any(kind == "user" for kind, _ in found.entities)
    assert ("process:beacon.exe", "ip:203.0.113.9") in found.edges


def test_alert_without_event_falls_back_to_host_and_source_ip():
    found = alert_entities(None, "web-01", "198.51.100.7")
    assert found.entities == [("host", "web-01"), ("ip", "198.51.100.7")]
    assert found.edges == [("host:web-01", "ip:198.51.100.7")]


async def test_entity_graph_endpoint_orders_steps_and_marks_first_seen(case_env, monkeypatch):
    from app.api.routes import case_graph as route

    async def no_event(_doc_id):
        return None
    monkeypatch.setattr(route, "es_get_log", no_event)
    env = case_env
    response = await env.client.get(f"/api/cases/{env.case.id}/entity-graph")
    assert response.status_code == 200
    body = response.json()
    assert [s["alert_id"] for s in body["steps"]] == [str(env.alerts[0].id), str(env.alerts[1].id)]
    nodes = {n["key"]: n for n in body["nodes"]}
    assert nodes["host:host0"]["first_step"] == 0 and nodes["host:host1"]["first_step"] == 1
    assert nodes["host:host0"]["facts"]["Status"] == "online"
    assert body["truncated"] == 0


async def test_add_case_ioc_normalises_and_is_idempotent(case_env):
    env = case_env
    first = await env.client.post(f"/api/cases/{env.case.id}/iocs", json={"kind": "hash", "value": SHA.upper()})
    again = await env.client.post(f"/api/cases/{env.case.id}/iocs", json={"kind": "hash", "value": SHA})
    assert first.status_code == again.status_code == 200
    assert first.json()["added"] is True and again.json()["added"] is False
    assert f"hash:{SHA}" in again.json()["ioc_data"]["ioc_keys"]
    host = await env.client.post(f"/api/cases/{env.case.id}/iocs", json={"kind": "host", "value": "FIN-WS-07"})
    assert "FIN-WS-07" in host.json()["ioc_data"]["affected_hosts"]
    bad = await env.client.post(f"/api/cases/{env.case.id}/iocs", json={"kind": "ip", "value": "not-an-ip"})
    assert bad.status_code == 422

import json
import threading
import time

import pytest
import yaml

from security import recursion_access_test as acl
import app as dashboard


def allowed():
    return dict(responded=True, rcode="NOERROR", rd=True, ra=True,
                answers=["93.184.215.14"], answer_count=1, error=None)


def denied():
    return dict(responded=True, rcode="REFUSED", rd=True, ra=False,
                answers=[], answer_count=0, error=None)


@pytest.mark.parametrize("a,u,status", [
    (allowed(), denied(), "PASS"), (allowed(), allowed(), "FAIL"),
    (denied(), denied(), "FAIL"), (acl.error_probe("TIMEOUT"), denied(), "INCONCLUSIVE"),
    (allowed(), acl.error_probe("CLIENT_UNAVAILABLE"), "INCONCLUSIVE"),
    (allowed(), dict(denied(), rcode="SERVFAIL"), "INCONCLUSIVE"),
    (acl.error_probe("TIMEOUT"), allowed(), "FAIL"),
])
def test_outcomes(a, u, status):
    assert acl.build_report(a, u)["status"] == status


def test_requires_valid_a_answer():
    assert acl.access_decision(dict(allowed(), answers=["alias.example."])) == "INCONCLUSIVE"
    assert acl.access_decision(dict(allowed(), ra=False)) == "INCONCLUSIVE"
    assert acl.access_decision(dict(denied(), answers=["93.184.215.14"])) == "INCONCLUSIVE"


def test_source_bound_fixed_probe(monkeypatch):
    calls = []
    monkeypatch.setattr(acl, "recursive_probe", lambda *a, **k: calls.append((a, k)) or allowed())
    acl.probe_client("authorised")
    acl.probe_client("unauthorised")
    assert calls[0] == (("10.10.0.2",), dict(domain="example.com", timeout=2, source="10.10.0.20"))
    assert calls[1][0] == ("10.20.0.2",)
    assert calls[1][1]["source"] == "10.20.0.30"


def test_missing_worker(tmp_path):
    result = acl.request_external(tmp_path, wait_seconds=0.01)
    assert acl.access_decision(result) == "INCONCLUSIVE"
    assert "CLIENT_UNAVAILABLE" in result["error"]
    assert not list(tmp_path.iterdir())


def test_mailbox_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(acl, "probe_client", lambda role: dict(denied(), source="10.20.0.30", server="10.20.0.2"))
    def serve():
        deadline = time.monotonic() + 2
        while not list(tmp_path.glob("*.request")) and time.monotonic() < deadline:
            time.sleep(0.01)
        acl.worker_once(tmp_path)
    worker = threading.Thread(target=serve)
    worker.start()
    result = acl.request_external(tmp_path, wait_seconds=2)
    worker.join(timeout=3)
    assert acl.access_decision(result) == "DENIED"


def test_worker_rejects_arbitrary_arguments(monkeypatch, tmp_path):
    path = tmp_path / ("a" * 32 + ".request")
    acl.atomic_json(path, dict(id="a" * 32, created=time.time(), command="whoami"))
    monkeypatch.setattr(acl, "probe_client", lambda role: pytest.fail("Must not query"))
    acl.worker_once(tmp_path)
    assert not list(tmp_path.iterdir())


@pytest.fixture
def config():
    return yaml.safe_load((acl.BASE / "config/targets.yaml").read_text())


@pytest.mark.parametrize("setting,value", [("allow_spoofing", True),
    ("allow_stress_testing", True), ("max_targets", 1), ("rate_limit_enabled", False)])
def test_safety(config, setting, value):
    config["safety"][setting] = value
    with pytest.raises(ValueError):
        acl.verify_policy(config)


def test_report_preserves_assessment(monkeypatch, tmp_path, config):
    assessment = tmp_path / "assessment.json"
    assessment.write_text("existing evidence")
    monkeypatch.setattr(acl, "probe_client", lambda role: allowed())
    monkeypatch.setattr(acl, "request_external", denied)
    report = acl.run_verification(config, tmp_path)
    assert report["status"] == "PASS"
    assert json.loads((tmp_path / "recursion_access_control.json").read_text()) == report
    assert assessment.read_text() == "existing evidence"


def test_endpoint_and_download(monkeypatch, tmp_path):
    report = acl.build_report(allowed(), denied())
    monkeypatch.setattr(dashboard, "REPORT_DIR", str(tmp_path))
    def run(config, directory):
        acl.atomic_json(tmp_path / "recursion_access_control.json", report)
        return report
    monkeypatch.setattr(dashboard, "run_verification", run)
    client = dashboard.app.test_client()
    assert client.post("/api/verify-recursion-acl").json["data"]["status"] == "PASS"
    assert client.get("/download/recursion-acl").json == report
    for payload in [[], None, {"ip": "8.8.8.8"}, {"command": "whoami"}]:
        assert client.post("/api/verify-recursion-acl", data=json.dumps(payload),
                           content_type="application/json").status_code == 400
    dashboard.acl_probe_lock.acquire()
    try:
        assert client.post("/api/verify-recursion-acl").status_code == 429
    finally:
        dashboard.acl_probe_lock.release()


def test_existing_endpoint_safety(monkeypatch, config, tmp_path):
    config["safety"]["allow_spoofing"] = True
    (tmp_path / "config").mkdir()
    (tmp_path / "config/targets.yaml").write_text(yaml.safe_dump(config))
    monkeypatch.setattr(dashboard, "BASE_DIR", str(tmp_path))
    client = dashboard.app.test_client()
    assert client.post("/api/lab-probe", json={"target": "recursive"}).status_code == 500
    assert client.post("/api/lab-probe", json={"target": "8.8.8.8"}).status_code == 400


def test_compose_network_isolation():
    compose = yaml.safe_load((acl.BASE / "docker-compose.yml").read_text())
    services = compose["services"]
    assert set(services["unauthorized-dns-client"]["networks"]) == {"external-test"}
    assert compose["networks"]["external-test"]["internal"] is True
    for service, address in [("dns-probe", "10.10.0.20"), ("recursive-dns", "10.10.0.2"),
                             ("authoritative-dns", "10.10.0.3"), ("refused-dns", "10.10.0.4")]:
        assert services[service]["networks"]["dns-lab"]["ipv4_address"] == address
    assert services["recursive-dns"]["networks"]["external-test"]["ipv4_address"] == "10.20.0.2"
    assert "10.10.0.5" not in [n["ipv4_address"] for s in services.values() for n in s["networks"].values()]

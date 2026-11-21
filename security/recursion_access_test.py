"""Fixed, real client-originated recursion probes; no Docker socket or exec API."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import time
import uuid

from probes.recursive_probe import recursive_probe

BASE = Path(__file__).resolve().parents[1]
DOMAIN = "example.com"
CLIENTS = {
    "authorised": ("10.10.0.20", "10.10.0.2", "ALLOWED"),
    "unauthorised": ("10.20.0.30", "10.20.0.2", "DENIED"),
}
LIMITATIONS = [
    "UDP IPv4 example.com A only; a cached answer demonstrates access, not a fresh upstream lookup.",
    "IP-based policy only: no client authentication, DNSSEC validation, spoofing detection or comprehensive attack resistance.",
    "Missing worker, network failure and timeout are inconclusive, never evidence of denial.",
]


def exchange_dir():
    return Path(os.environ.get("ACL_EXCHANGE_DIR", "/acl-exchange"))


def atomic_json(path, data):
    path = Path(path)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    temporary.replace(path)


def error_probe(error):
    return dict(responded=False, rcode=None, rd=None, ra=None, aa=None,
                answer_count=0, answers=[], error=str(error))


def access_decision(probe):
    if not probe.get("responded") or probe.get("error"):
        return "INCONCLUSIVE"
    # A valid IPv4 answer is required, rather than a CNAME or answer count alone.
    valid_a = False
    for answer in probe.get("answers", []):
        try:
            ipaddress.IPv4Address(answer)
            valid_a = True
        except (ValueError, TypeError):
            pass
    if (probe.get("rcode") == "NOERROR" and probe.get("rd") is True
            and probe.get("ra") is True and valid_a):
        return "ALLOWED"
    if probe.get("rcode") == "REFUSED" and not probe.get("answers"):
        return "DENIED"
    return "INCONCLUSIVE"


def overall_status(authorised, unauthorised):
    if authorised == "DENIED" or unauthorised == "ALLOWED":
        return "FAIL"
    if authorised == "ALLOWED" and unauthorised == "DENIED":
        return "PASS"
    return "INCONCLUSIVE"


def probe_client(role):
    source, server, _ = CLIENTS[role]
    # Binding a local interface is not spoofing. A wrong container cannot bind it.
    result = recursive_probe(server, domain=DOMAIN, timeout=2, source=source)
    result.update(source=source, server=server, query_type="A", query_rd=True,
                  attempts=1, transport="udp")
    return result


def request_external(directory=None, wait_seconds=8):
    directory = Path(directory) if directory is not None else exchange_dir()
    request_id = uuid.uuid4().hex
    request = directory / (request_id + ".request")
    response = directory / (request_id + ".response")
    try:
        if not directory.is_dir():
            return error_probe("CLIENT_UNAVAILABLE: shared mailbox is not mounted")
        atomic_json(request, {"id": request_id, "created": time.time()})
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if response.exists():
                data = json.loads(response.read_text(encoding="utf-8"))
                if (data.get("id") != request_id
                        or not isinstance(data.get("probe"), dict)
                        or data["probe"].get("source") != CLIENTS["unauthorised"][0]
                        or data["probe"].get("server") != CLIENTS["unauthorised"][1]):
                    return error_probe("INVALID_WORKER_EVIDENCE")
                return data["probe"]
            time.sleep(0.1)
        return error_probe("CLIENT_UNAVAILABLE: worker missing, unreachable or timed out")
    except (OSError, ValueError, TypeError) as error:
        return error_probe(error)
    finally:
        for path in (request, response):
            path.unlink(missing_ok=True)


def worker_once(directory=None):
    directory = Path(directory) if directory is not None else exchange_dir()
    for request in directory.glob("*.request"):
        if not re.fullmatch(r"[0-9a-f]{32}", request.stem):
            continue
        try:
            data = json.loads(request.read_text(encoding="utf-8"))
            # Request contains no command, address, domain, or other probe arguments.
            if (set(data) != {"id", "created"} or data["id"] != request.stem
                    or not 0 <= time.time() - data["created"] <= 10):
                continue
            atomic_json(request.with_suffix(".response"),
                        {"id": request.stem, "probe": probe_client("unauthorised")})
            time.sleep(0.5)  # At most two fixed DNS queries per second.
        except (OSError, ValueError, TypeError):
            pass
        finally:
            request.unlink(missing_ok=True)
    # Remove late responses after cancelled requests without retaining stale evidence.
    for response in directory.glob("*.response"):
        try:
            if time.time() - response.stat().st_mtime > 30:
                response.unlink(missing_ok=True)
        except FileNotFoundError:
            pass  # The app can consume a response concurrently.


def verify_policy(config):
    safety = config["safety"]
    if (len(config["targets"]) > min(safety.get("max_targets", 20), 20)
            or safety.get("allow_spoofing", False)
            or safety.get("allow_stress_testing", False)
            or safety.get("rate_limit_enabled", True) is not True):
        raise ValueError("Unsafe laboratory configuration.")
    if not any(item["ip"] == "10.10.0.2" for item in config["targets"]):
        raise ValueError("Recursive lab target is not enabled.")


def build_report(authorised, unauthorised):
    tests = {}
    for role, probe in (("authorised", authorised), ("unauthorised", unauthorised)):
        source, server, expected = CLIENTS[role]
        decision = access_decision(probe)
        tests[role] = dict(client=source, server=server, port=53, expected=expected,
                           observed=decision, access_decision=decision, probe=probe)
    return dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
                trusted_subnet="10.10.0.0/24", untrusted_subnet="10.20.0.0/24",
                query=dict(domain=DOMAIN, type="A", rd=True), tests=tests,
                status=overall_status(tests["authorised"]["observed"],
                                      tests["unauthorised"]["observed"]),
                errors=[p["error"] for p in (authorised, unauthorised) if p.get("error")],
                limitations=LIMITATIONS)


def run_verification(config, report_dir=None):
    verify_policy(config)
    authorised = probe_client("authorised")
    time.sleep(0.5)
    unauthorised = request_external()
    time.sleep(0.5)
    report = build_report(authorised, unauthorised)
    directory = Path(report_dir) if report_dir is not None else BASE / "artifacts/results"
    directory.mkdir(parents=True, exist_ok=True)
    atomic_json(directory / "recursion_access_control.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--client", choices=CLIENTS)
    args = parser.parse_args()
    if args.worker:
        while True:
            worker_once()
            time.sleep(0.1)
    elif args.client:
        print(json.dumps(probe_client(args.client), indent=2))
    else:
        import yaml
        config = yaml.safe_load((BASE / "config/targets.yaml").read_text(encoding="utf-8"))
        print(json.dumps(run_verification(config), indent=2))


if __name__ == "__main__":
    main()

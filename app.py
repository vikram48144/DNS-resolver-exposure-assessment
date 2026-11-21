from flask import Flask, render_template, jsonify, send_from_directory
import json
import os
import subprocess
import threading
import time
import yaml
from probes.recursive_probe import recursive_probe
from probes.authoritative_probe import authoritative_probe
from classifier.classifier import classify_dns_server
from main import run_probe_with_retries
from security.recursion_access_test import run_verification
from classifier.classifier import classify_dns_server

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "artifacts", "results")
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")

LAB_TARGETS = {
    "recursive": ("Recursive DNS", "10.10.0.2"),
    "authoritative": ("Authoritative-only DNS", "10.10.0.3"),
    "refused": ("Refused DNS", "10.10.0.4"),
    "inconclusive": ("Inconclusive DNS", "10.10.0.5")
}
lab_probe_lock = threading.Lock()
lab_last_query = 0.0
acl_probe_lock = threading.Lock()


@app.route("/api/verify-recursion-acl", methods=["POST"])
def verify_recursion_acl():
    from flask import request
    if request.get_data() and request.get_json(silent=True) != {}:
        return jsonify(success=False, message="This fixed lab test accepts no arguments."), 400
    if not acl_probe_lock.acquire(blocking=False):
        return jsonify(success=False, message="ACL verification is already running."), 429
    try:
        with open(os.path.join(BASE_DIR, "config", "targets.yaml"), encoding="utf-8") as file:
            config = yaml.safe_load(file)
        report = run_verification(config, REPORT_DIR)
        return jsonify(success=True, data=report)
    except ValueError as error:
        return jsonify(success=False, message=str(error)), 400
    except Exception as error:
        return jsonify(success=False, message=str(error)), 500
    finally:
        acl_probe_lock.release()


@app.route("/download/recursion-acl")
def download_recursion_acl():
    return send_from_directory(REPORT_DIR, "recursion_access_control.json", as_attachment=True)


@app.route("/api/lab-probe", methods=["POST"])
def lab_probe():
    """Probe only the predefined lab targets, retaining both sets of evidence."""
    from flask import request

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(success=False, message="Provide a JSON object with a lab target."), 400
    target = data.get("target")
    if not isinstance(target, str) or target not in LAB_TARGETS:
        return jsonify(success=False, message="Invalid authorised lab target."), 400
    if set(data) - {"target"}:
        return jsonify(success=False, message="Only a predefined target may be supplied."), 400
    if not lab_probe_lock.acquire(blocking=False):
        return jsonify(success=False, message="A lab probe is running. Please wait and retry."), 429

    try:
        with open(os.path.join(BASE_DIR, "config", "targets.yaml"), encoding="utf-8") as file:
            config = yaml.safe_load(file)
        safety = config["safety"]
        settings = config["settings"]
        if (len(config["targets"]) > safety.get("max_targets", 20)
                or safety.get("allow_spoofing", False)
                or safety.get("allow_stress_testing", False)):
            raise ValueError("Unsafe laboratory configuration.")
        name, ip = LAB_TARGETS[target]
        if not any(item["ip"] == ip for item in config["targets"]):
            raise ValueError("Selected target is not enabled in the lab configuration.")
        timeout = float(settings.get("timeout", 2))
        retries = int(settings.get("retries", 2))
        rate = float(settings.get("queries_per_second", 2))
        if timeout <= 0 or retries < 0 or rate <= 0:
            raise ValueError("Lab timeout and query rate must be positive, and retries nonnegative.")

        def paced_probe(probe, **kwargs):
            global lab_last_query
            time.sleep(max(0, lab_last_query + 1 / rate - time.monotonic()))
            lab_last_query = time.monotonic()
            return probe(**kwargs)

        def run(probe, domain):
            return run_probe_with_retries(
                lambda **kwargs: paced_probe(probe, **kwargs),
                retries=retries, server_ip=ip, domain=domain, port=53, timeout=timeout
            )

        recursive = run(recursive_probe, "example.com")
        authoritative = run(authoritative_probe, "www.lab.example")
        return jsonify(
            success=True, target=target, name=name, ip=ip,
            classification=classify_dns_server(recursive, authoritative),
            recursive_probe=recursive, authoritative_probe=authoritative
        )
    except Exception as error:
        return jsonify(success=False, message=str(error)), 500
    finally:
        lab_probe_lock.release()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/results")
def get_results():
    report_path = os.path.join(REPORT_DIR, "assessment.json")

    if not os.path.exists(report_path):
        return jsonify({
            "success": False,
            "message": "No assessment report found."
        }), 404

    try:
        with open(report_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        return jsonify({
            "success": True,
            "data": data
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


@app.route("/api/run", methods=["POST"])
def run_assessment():
    try:
        process = subprocess.run(
            ["python", "-u", "main.py"],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=60
        )

        if process.returncode != 0:
            return jsonify({
                "success": False,
                "message": "Assessment failed.",
                "output": process.stdout,
                "error": process.stderr
            }), 500

        report_path = os.path.join(REPORT_DIR, "assessment.json")

        if not os.path.exists(report_path):
            return jsonify({
                "success": False,
                "message": "Assessment completed but no JSON report was generated.",
                "output": process.stdout
            }), 500

        with open(report_path, "r", encoding="utf-8") as file:
            report = json.load(file)

        return jsonify({
            "success": True,
            "message": "Assessment completed successfully.",
            "output": process.stdout,
            "data": report
        })

    except subprocess.TimeoutExpired:
        return jsonify({
            "success": False,
            "message": "Assessment timed out."
        }), 504

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500


@app.route("/download/json")
def download_json():
    return send_from_directory(
        REPORT_DIR,
        "assessment.json",
        as_attachment=True
    )


@app.route("/download/csv")
def download_csv():
    return send_from_directory(
        REPORT_DIR,
        "assessment.csv",
        as_attachment=True
    )


@app.route("/download/packet-analysis")
def download_packet_analysis():
    return send_from_directory(
        CAPTURE_DIR,
        "packet_analysis.txt",
        as_attachment=True
    )


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "DNS Resolver Exposure Assessment"
    })

@app.route("/api/domain-probe", methods=["POST"])
def domain_probe():
    """
    Resolve a user-supplied domain through the authorised
    recursive DNS resolver in the controlled lab.

    The target resolver remains fixed at 10.10.0.2.
    This endpoint does not scan arbitrary DNS servers.
    """

    from flask import request
    import re

    data = request.get_json(silent=True) or {}

    domain = str(data.get("domain", "")).strip().lower()

    if not domain:
        return jsonify({
            "success": False,
            "message": "Please provide a domain name."
        }), 400

    # Remove trailing dot if supplied.
    domain = domain.rstrip(".")

    # Basic domain validation.
    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}$"
    )

    if not domain_pattern.match(domain):
        return jsonify({
            "success": False,
            "message": "Invalid domain name."
        }), 400

    # IMPORTANT:
    # The DNS SERVER being assessed remains our authorised
    # recursive lab resolver.
    resolver_ip = "10.10.0.2"

    try:
        result = recursive_probe(
            resolver_ip,
            domain=domain,
            port=53,
            timeout=3
        )

        classification = "INCONCLUSIVE"

        if (
            result["responded"]
            and result["rcode"] == "NOERROR"
            and result["ra"] is True
            and result["answer_count"] > 0
        ):
            classification = "RECURSIVE"

        elif (
            result["responded"]
            and result["rcode"] == "REFUSED"
        ):
            classification = "REFUSED"

        return jsonify({
            "success": True,
            "domain": domain,
            "resolver": resolver_ip,
            "classification": classification,
            "result": result
        })

    except Exception as error:
        return jsonify({
            "success": False,
            "message": str(error)
        }), 500

    
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

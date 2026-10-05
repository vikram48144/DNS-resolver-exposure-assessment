from flask import Flask, render_template, jsonify, send_from_directory
import json
import os
import subprocess
from probes.recursive_probe import recursive_probe

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, "reporting", "results")
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")


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
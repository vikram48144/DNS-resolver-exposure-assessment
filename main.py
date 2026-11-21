import time
import yaml

from probes.recursive_probe import recursive_probe
from probes.authoritative_probe import authoritative_probe
from classifier.classifier import classify_dns_server

from reporting.report import (
    generate_json_report,
    generate_csv_report
)

from reporting.logger import (
    setup_logger,
    log_probe_result,
    log_classification
)


# ============================================================
# PROBE WITH RETRY SUPPORT
# ============================================================

def run_probe_with_retries(
    probe_function,
    retries,
    **kwargs
):
    """
    Execute a DNS probe with retry support.

    retries=2 means:
        1 initial attempt
        + 2 retries
        = maximum 3 attempts

    A valid DNS response is not retried.
    """

    attempts = 0
    result = None

    while attempts <= retries:

        attempts += 1

        result = probe_function(
            **kwargs
        )

        if result["responded"]:
            break

    result["attempts"] = attempts

    return result


# ============================================================
# MAIN ASSESSMENT
# ============================================================

def main():

    # --------------------------------------------------------
    # LOAD CONFIGURATION
    # --------------------------------------------------------

    with open(
        "config/targets.yaml",
        "r",
        encoding="utf-8"
    ) as file:

        config = yaml.safe_load(
            file
        )

    targets = config["targets"]
    settings = config["settings"]
    safety = config["safety"]

    # --------------------------------------------------------
    # SETUP EVIDENCE LOGGER
    # --------------------------------------------------------

    logger = setup_logger()

    # --------------------------------------------------------
    # SAFETY CONTROLS
    # --------------------------------------------------------

    max_targets = safety.get(
        "max_targets",
        20
    )

    if len(targets) > max_targets:

        raise ValueError(
            f"Safety limit exceeded. "
            f"Configured targets: {len(targets)}, "
            f"maximum allowed: {max_targets}"
        )

    if safety.get(
        "allow_spoofing",
        False
    ):

        raise ValueError(
            "Unsafe configuration: "
            "spoofing must remain disabled."
        )

    if safety.get(
        "allow_stress_testing",
        False
    ):

        raise ValueError(
            "Unsafe configuration: "
            "stress testing must remain disabled."
        )

    # --------------------------------------------------------
    # SETTINGS
    # --------------------------------------------------------

    timeout = settings.get(
        "timeout",
        2
    )

    retries = settings.get(
        "retries",
        2
    )

    queries_per_second = settings.get(
        "queries_per_second",
        2
    )

    test_zone = config[
        "test_zone"
    ]

    controlled_domain = (
        f"www.{test_zone}"
    )

    results = []

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    print()
    print("=" * 72)

    print(
        "       AUTHORISED DNS RESOLVER "
        "EXPOSURE ASSESSMENT"
    )

    print("=" * 72)

    # --------------------------------------------------------
    # TEST EACH AUTHORISED TARGET
    # --------------------------------------------------------

    for target in targets:

        name = target["name"]
        ip = target["ip"]

        port = target.get(
            "port",
            53
        )

        print()
        print(
            f"Testing: {name} ({ip})"
        )

        # ====================================================
        # RECURSIVE PROBE
        # ====================================================

        recursive_result = (
            run_probe_with_retries(
                recursive_probe,
                retries=retries,
                server_ip=ip,
                domain="example.com",
                port=port,
                timeout=timeout
            )
        )

        # ----------------------------------------------------
        # LOG RECURSIVE EVIDENCE
        # ----------------------------------------------------

        log_probe_result(
            logger=logger,
            target_name=name,
            target_ip=ip,
            probe_type="recursive",
            query_name="example.com",
            result=recursive_result
        )

        # ----------------------------------------------------
        # RATE CONTROL
        # ----------------------------------------------------

        if queries_per_second > 0:

            time.sleep(
                1 / queries_per_second
            )

        # ====================================================
        # AUTHORITATIVE PROBE
        # ====================================================

        authoritative_result = (
            run_probe_with_retries(
                authoritative_probe,
                retries=retries,
                server_ip=ip,
                domain=controlled_domain,
                port=port,
                timeout=timeout
            )
        )

        # ----------------------------------------------------
        # LOG AUTHORITATIVE EVIDENCE
        # ----------------------------------------------------

        log_probe_result(
            logger=logger,
            target_name=name,
            target_ip=ip,
            probe_type="authoritative",
            query_name=controlled_domain,
            result=authoritative_result
        )

        # ====================================================
        # CLASSIFICATION
        # ====================================================

        classification = (
            classify_dns_server(
                recursive_result,
                authoritative_result
            )
        )

        expected = target.get(
            "expected",
            "UNKNOWN"
        )

        if classification == expected:

            validation = "PASS"

        else:

            validation = "FAIL"

        # ----------------------------------------------------
        # LOG FINAL CLASSIFICATION
        # ----------------------------------------------------

        log_classification(
            logger=logger,
            target_name=name,
            target_ip=ip,
            classification=classification,
            expected=expected,
            validation=validation
        )

        # ====================================================
        # STORE STRUCTURED RESULT
        # ====================================================

        result = {

            "name":
                name,

            "ip":
                ip,

            "recursive_probe":
                recursive_result,

            "authoritative_probe":
                authoritative_result,

            "classification":
                classification,

            "expected":
                expected,

            "validation":
                validation
        }

        results.append(
            result
        )

        # ====================================================
        # DISPLAY EVIDENCE
        # ====================================================

        print("-" * 72)

        print(
            f"Recursive RCODE : "
            f"{recursive_result['rcode'] or recursive_result['error']}"
        )

        print(
            f"RA flag         : "
            f"{recursive_result['ra']}"
        )

        print(
            f"Recursive ans.  : "
            f"{recursive_result['answer_count']}"
        )

        print(
            f"Recursive tries : "
            f"{recursive_result['attempts']}"
        )

        print()

        print(
            f"Auth RCODE      : "
            f"{authoritative_result['rcode'] or authoritative_result['error']}"
        )

        print(
            f"AA flag         : "
            f"{authoritative_result['aa']}"
        )

        print(
            f"Auth answers    : "
            f"{authoritative_result['answer_count']}"
        )

        print(
            f"Auth tries      : "
            f"{authoritative_result['attempts']}"
        )

        print()

        print(
            f"Classification  : "
            f"{classification}"
        )

        print(
            f"Expected        : "
            f"{expected}"
        )

        print(
            f"Ground Truth    : "
            f"{validation}"
        )

        print("-" * 72)

        # ----------------------------------------------------
        # RATE CONTROL BETWEEN TARGETS
        # ----------------------------------------------------

        if queries_per_second > 0:

            time.sleep(
                1 / queries_per_second
            )

    # ========================================================
    # GROUND-TRUTH VALIDATION
    # ========================================================

    total = len(
        results
    )

    correct = sum(
        result["validation"] == "PASS"
        for result in results
    )

    incorrect = (
        total - correct
    )

    print()
    print("=" * 72)
    print("GROUND-TRUTH VALIDATION")
    print("=" * 72)

    print(
        f"Cases tested : {total}"
    )

    print(
        f"Correct      : {correct}"
    )

    print(
        f"Incorrect    : {incorrect}"
    )

    if total > 0:

        accuracy = (
            correct / total
        ) * 100

        print(
            f"Accuracy     : "
            f"{accuracy:.2f}%"
        )

    else:

        print(
            "Accuracy     : N/A"
        )

    print("=" * 72)

    # ========================================================
    # GENERATE EXPOSURE REPORTS
    # ========================================================

    json_path = (
        generate_json_report(
            results,
            config
        )
    )

    csv_path = (
        generate_csv_report(
            results
        )
    )

    print()
    print("=" * 72)
    print("EXPOSURE REPORTS")
    print("=" * 72)

    print(
        f"JSON report : "
        f"{json_path}"
    )

    print(
        f"CSV report  : "
        f"{csv_path}"
    )

    print(
        "Evidence log: "
        "artifacts/logs/dns_assessment.log"
    )

    print("=" * 72)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
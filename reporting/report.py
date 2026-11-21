import csv
import json
import os
from datetime import datetime, timezone


def exposure_interpretation(classification):
    """
    Return a human-readable interpretation of
    the observed DNS behaviour.
    """

    interpretations = {

        "RECURSIVE":
            "Recursion was demonstrated from the designated "
            "external lab client. Resolver configuration should "
            "be reviewed to confirm that this exposure is intended.",

        "AUTHORITATIVE_ONLY":
            "Authoritative DNS behaviour was observed for the "
            "controlled test zone. External recursion was not "
            "demonstrated.",

        "REFUSED":
            "The DNS server was reachable but explicitly refused "
            "the tested queries.",

        "INCONCLUSIVE":
            "Insufficient DNS response evidence was obtained. "
            "This result must not be interpreted as proof that "
            "recursion is disabled."
    }

    return interpretations.get(
        classification,
        "Unknown classification."
    )


def generate_json_report(results, config):
    """
    Generate detailed machine-readable JSON report.
    """

    os.makedirs(
        "artifacts/results",
        exist_ok=True
    )

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    report = {
        "assessment": {
            "title":
                "Authorised DNS Resolver Exposure Assessment",

            "timestamp_utc":
                timestamp,

            "test_zone":
                config["test_zone"],

            "target_count":
                len(results),

            "max_targets":
                config["safety"]["max_targets"],

            "queries_per_second":
                config["settings"]["queries_per_second"],

            "timeout_seconds":
                config["settings"]["timeout"],

            "retries":
                config["settings"]["retries"]
        },

        "results": []
    }

    for result in results:

        entry = {
            "name":
                result["name"],

            "ip":
                result["ip"],

            "classification":
                result["classification"],

            "expected":
                result["expected"],

            "validation":
                result["validation"],

            "interpretation":
                exposure_interpretation(
                    result["classification"]
                ),

            "recursive_probe":
                result["recursive_probe"],

            "authoritative_probe":
                result["authoritative_probe"]
        }

        report["results"].append(entry)

    path = "artifacts/results/assessment.json"

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return path


def generate_csv_report(results):
    """
    Generate summary CSV report.
    """

    os.makedirs(
        "artifacts/results",
        exist_ok=True
    )

    path = "artifacts/results/assessment.csv"

    fieldnames = [
        "name",
        "ip",
        "recursive_rcode",
        "recursive_ra",
        "recursive_answers",
        "recursive_attempts",
        "authoritative_rcode",
        "authoritative_aa",
        "authoritative_answers",
        "authoritative_attempts",
        "classification",
        "expected",
        "validation",
        "interpretation"
    ]

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for result in results:

            recursive = result[
                "recursive_probe"
            ]

            authoritative = result[
                "authoritative_probe"
            ]

            writer.writerow({

                "name":
                    result["name"],

                "ip":
                    result["ip"],

                "recursive_rcode":
                    recursive["rcode"]
                    or recursive["error"],

                "recursive_ra":
                    recursive["ra"],

                "recursive_answers":
                    recursive["answer_count"],

                "recursive_attempts":
                    recursive.get(
                        "attempts",
                        1
                    ),

                "authoritative_rcode":
                    authoritative["rcode"]
                    or authoritative["error"],

                "authoritative_aa":
                    authoritative["aa"],

                "authoritative_answers":
                    authoritative[
                        "answer_count"
                    ],

                "authoritative_attempts":
                    authoritative.get(
                        "attempts",
                        1
                    ),

                "classification":
                    result["classification"],

                "expected":
                    result["expected"],

                "validation":
                    result["validation"],

                "interpretation":
                    exposure_interpretation(
                        result["classification"]
                    )
            })

    return path
import os
import logging
from datetime import datetime, timezone


LOG_DIRECTORY = "artifacts/logs"
LOG_FILE = os.path.join(
    LOG_DIRECTORY,
    "dns_assessment.log"
)


def setup_logger():
    """
    Create the assessment evidence logger.
    """

    os.makedirs(
        LOG_DIRECTORY,
        exist_ok=True
    )

    logger = logging.getLogger(
        "dns_assessment"
    )

    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if setup_logger()
    # is called more than once.
    if not logger.handlers:

        file_handler = logging.FileHandler(
            LOG_FILE,
            encoding="utf-8"
        )

        formatter = logging.Formatter(
            "%(message)s"
        )

        file_handler.setFormatter(
            formatter
        )

        logger.addHandler(
            file_handler
        )

    return logger


def log_probe_result(
    logger,
    target_name,
    target_ip,
    probe_type,
    query_name,
    result
):
    """
    Record structured evidence for one DNS probe.
    """

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    answers = result.get(
        "answers",
        []
    )

    answer_text = (
        ",".join(answers)
        if answers
        else "-"
    )

    logger.info(
        "timestamp=%s "
        "target_name=%s "
        "target_ip=%s "
        "probe=%s "
        "query=%s "
        "responded=%s "
        "rcode=%s "
        "RD=%s "
        "RA=%s "
        "AA=%s "
        "answer_count=%s "
        "answers=%s "
        "attempts=%s "
        "error=%s",
        timestamp,
        target_name,
        target_ip,
        probe_type,
        query_name,
        result.get("responded"),
        result.get("rcode"),
        result.get("rd"),
        result.get("ra"),
        result.get("aa"),
        result.get("answer_count"),
        answer_text,
        result.get("attempts", 1),
        result.get("error")
    )


def log_classification(
    logger,
    target_name,
    target_ip,
    classification,
    expected,
    validation
):
    """
    Record the final classification for a target.
    """

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    logger.info(
        "timestamp=%s "
        "target_name=%s "
        "target_ip=%s "
        "event=classification "
        "classification=%s "
        "expected=%s "
        "validation=%s",
        timestamp,
        target_name,
        target_ip,
        classification,
        expected,
        validation
    )
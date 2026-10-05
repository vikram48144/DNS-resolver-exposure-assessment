import dns.message
import dns.query
import dns.flags
import dns.rcode
import dns.exception
import dns.rdatatype


def authoritative_probe(
    server_ip,
    domain="www.lab.example",
    port=53,
    timeout=2
):
    """
    Test whether a DNS server provides an authoritative
    answer for the controlled test zone.

    The query is sent with RD=0 because this probe is
    specifically testing authoritative behaviour rather
    than recursive resolution.
    """

    result = {
        "server": server_ip,
        "domain": domain,
        "responded": False,
        "rcode": None,
        "rd": False,
        "ra": False,
        "aa": False,
        "answer_count": 0,
        "answers": [],
        "error": None
    }

    # -------------------------------------------------
    # 1. Create DNS query
    # -------------------------------------------------

    query = dns.message.make_query(
        domain,
        dns.rdatatype.A
    )

    # Disable Recursion Desired (RD).
    # We want to determine whether THIS server itself
    # is authoritative for the controlled test zone.
    query.flags &= ~dns.flags.RD

    try:

        # -------------------------------------------------
        # 2. Send DNS query
        # -------------------------------------------------

        response = dns.query.udp(
            query,
            server_ip,
            port=port,
            timeout=timeout
        )

        result["responded"] = True

        # -------------------------------------------------
        # 3. Read DNS response code
        # -------------------------------------------------

        result["rcode"] = dns.rcode.to_text(
            response.rcode()
        )

        # -------------------------------------------------
        # 4. Inspect DNS flags
        # -------------------------------------------------

        result["rd"] = bool(
            response.flags & dns.flags.RD
        )

        result["ra"] = bool(
            response.flags & dns.flags.RA
        )

        result["aa"] = bool(
            response.flags & dns.flags.AA
        )

        # -------------------------------------------------
        # 5. Extract answers
        # -------------------------------------------------

        for answer_section in response.answer:

            for item in answer_section:

                result["answers"].append(
                    item.to_text()
                )

        result["answer_count"] = len(
            result["answers"]
        )

    # -------------------------------------------------
    # 6. Timeout handling
    # -------------------------------------------------

    except dns.exception.Timeout:

        result["error"] = "TIMEOUT"

    # -------------------------------------------------
    # 7. Other errors
    # -------------------------------------------------

    except Exception as error:

        result["error"] = str(error)

    return result


# =====================================================
# Standalone testing
# =====================================================

if __name__ == "__main__":

    import yaml
    import time

    # -------------------------------------------------
    # Load configuration
    # -------------------------------------------------

    with open("config/targets.yaml", "r") as file:
        config = yaml.safe_load(file)

    targets = config["targets"]
    settings = config["settings"]
    safety = config["safety"]

    timeout = settings.get(
        "timeout",
        2
    )

    queries_per_second = settings.get(
        "queries_per_second",
        2
    )

    max_targets = safety.get(
        "max_targets",
        20
    )

    # -------------------------------------------------
    # Safety check
    # -------------------------------------------------

    if len(targets) > max_targets:

        raise ValueError(
            f"Target count exceeds safety limit "
            f"of {max_targets}"
        )

    # -------------------------------------------------
    # Controlled test domain
    # -------------------------------------------------

    test_zone = config["test_zone"]

    test_domain = f"www.{test_zone}"

    print()
    print("=== DNS Authoritative Probe ===")
    print()

    # -------------------------------------------------
    # Probe every authorised target
    # -------------------------------------------------

    for target in targets:

        print(
            f"Testing {target['name']} "
            f"({target['ip']})"
        )

        result = authoritative_probe(
            server_ip=target["ip"],
            domain=test_domain,
            port=target.get("port", 53),
            timeout=timeout
        )

        # -------------------------------------------------
        # Display evidence
        # -------------------------------------------------

        for key, value in result.items():

            print(
                f"{key:15}: {value}"
            )

        print("-" * 50)

        # -------------------------------------------------
        # Rate limiting
        # -------------------------------------------------

        if queries_per_second > 0:

            time.sleep(
                1 / queries_per_second
            )
"""Probe recursive DNS resolvers."""
import dns.message
import dns.query
import dns.flags
import dns.rcode
import dns.exception


def recursive_probe(
    server_ip,
    domain="example.com",
    port=53,
    timeout=2
):
    """
    Send a DNS query with recursion requested (RD=1).

    Returns structured information about the DNS response.
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

    # -----------------------------------------
    # 1. Create DNS query
    # -----------------------------------------

    query = dns.message.make_query(
        domain,
        dns.rdatatype.A
    )

    # Explicitly request recursion
    query.flags |= dns.flags.RD

    try:

        # -----------------------------------------
        # 2. Send DNS query using UDP
        # -----------------------------------------

        response = dns.query.udp(
            query,
            server_ip,
            port=port,
            timeout=timeout
        )

        result["responded"] = True

        # -----------------------------------------
        # 3. Read DNS response code
        # -----------------------------------------

        result["rcode"] = dns.rcode.to_text(
            response.rcode()
        )

        # -----------------------------------------
        # 4. Inspect important DNS flags
        # -----------------------------------------

        result["rd"] = bool(
            response.flags & dns.flags.RD
        )

        result["ra"] = bool(
            response.flags & dns.flags.RA
        )

        result["aa"] = bool(
            response.flags & dns.flags.AA
        )

        # -----------------------------------------
        # 5. Extract answers
        # -----------------------------------------

        for answer_section in response.answer:

            for item in answer_section:

                result["answers"].append(
                    item.to_text()
                )

        result["answer_count"] = len(
            result["answers"]
        )

    # -----------------------------------------
    # 6. Timeout
    # -----------------------------------------

    except dns.exception.Timeout:

        result["error"] = "TIMEOUT"

    # -----------------------------------------
    # 7. Other network/DNS errors
    # -----------------------------------------

    except Exception as error:

        result["error"] = str(error)

    return result


# ------------------------------------------------
# Temporary test
# ------------------------------------------------

if __name__ == "__main__":

    import yaml
    import time

    # Load configuration
    with open("config/targets.yaml", "r") as file:
        config = yaml.safe_load(file)

    targets = config["targets"]
    settings = config["settings"]

    timeout = settings.get("timeout", 2)
    queries_per_second = settings.get("queries_per_second", 2)

    # Safety check
    max_targets = config["safety"].get("max_targets", 20)

    if len(targets) > max_targets:
        raise ValueError(
            f"Target count exceeds safety limit of {max_targets}"
        )

    print("\n=== DNS Recursive Probe ===\n")

    for target in targets:

        print(f"Testing {target['name']} ({target['ip']})")

        result = recursive_probe(
            server_ip=target["ip"],
            domain="example.com",
            port=target.get("port", 53),
            timeout=timeout
        )

        for key, value in result.items():
            print(f"{key:15}: {value}")

        print("-" * 50)

        # Rate limiting
        time.sleep(1 / queries_per_second)
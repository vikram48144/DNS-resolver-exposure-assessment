def classify_dns_server(recursive_result, authoritative_result):
    """
    Classify DNS server behaviour using evidence from
    the recursive and authoritative probes.

    Possible results:
        RECURSIVE
        AUTHORITATIVE_ONLY
        REFUSED
        INCONCLUSIVE
    """

    # No usable response from either test
    if (
        not recursive_result["responded"]
        and not authoritative_result["responded"]
    ):
        return "INCONCLUSIVE"

    # Successful recursive resolution
    if (
        recursive_result["responded"]
        and recursive_result["rcode"] == "NOERROR"
        and recursive_result["ra"] is True
        and recursive_result["answer_count"] > 0
    ):
        return "RECURSIVE"

    # Authoritative for our controlled zone,
    # while refusing recursive resolution
    if (
        authoritative_result["responded"]
        and authoritative_result["rcode"] == "NOERROR"
        and authoritative_result["aa"] is True
        and authoritative_result["answer_count"] > 0
        and recursive_result["responded"]
        and recursive_result["rcode"] == "REFUSED"
    ):
        return "AUTHORITATIVE_ONLY"

    # Explicit refusal of both probes
    if (
        recursive_result["responded"]
        and authoritative_result["responded"]
        and recursive_result["rcode"] == "REFUSED"
        and authoritative_result["rcode"] == "REFUSED"
    ):
        return "REFUSED"

    # Anything ambiguous
    return "INCONCLUSIVE"
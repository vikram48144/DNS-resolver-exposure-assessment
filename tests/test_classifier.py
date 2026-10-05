from classifier.classifier import classify_dns_server


# ============================================================
# HELPER
# ============================================================

def make_result(
    responded=True,
    rcode="NOERROR",
    ra=False,
    aa=False,
    answer_count=0
):
    """
    Create a simulated DNS probe result.

    This allows us to test classification logic without
    sending any real DNS traffic.
    """

    return {
        "responded": responded,
        "rcode": rcode,
        "ra": ra,
        "aa": aa,
        "answer_count": answer_count
    }


# ============================================================
# TEST 1: RECURSIVE DNS SERVER
# ============================================================

def test_recursive_server():

    recursive = make_result(
        responded=True,
        rcode="NOERROR",
        ra=True,
        aa=False,
        answer_count=2
    )

    authoritative = make_result(
        responded=True,
        rcode="NOERROR",
        ra=True,
        aa=False,
        answer_count=0
    )

    result = classify_dns_server(
        recursive,
        authoritative
    )

    assert result == "RECURSIVE"


# ============================================================
# TEST 2: AUTHORITATIVE-ONLY DNS SERVER
# ============================================================

def test_authoritative_only_server():

    recursive = make_result(
        responded=True,
        rcode="REFUSED",
        ra=False,
        aa=False,
        answer_count=0
    )

    authoritative = make_result(
        responded=True,
        rcode="NOERROR",
        ra=False,
        aa=True,
        answer_count=1
    )

    result = classify_dns_server(
        recursive,
        authoritative
    )

    assert result == "AUTHORITATIVE_ONLY"


# ============================================================
# TEST 3: REFUSED DNS SERVER
# ============================================================

def test_refused_server():

    recursive = make_result(
        responded=True,
        rcode="REFUSED",
        ra=False,
        aa=False,
        answer_count=0
    )

    authoritative = make_result(
        responded=True,
        rcode="REFUSED",
        ra=False,
        aa=False,
        answer_count=0
    )

    result = classify_dns_server(
        recursive,
        authoritative
    )

    assert result == "REFUSED"


# ============================================================
# TEST 4: COMPLETE TIMEOUT
# ============================================================

def test_timeout_is_inconclusive():

    recursive = make_result(
        responded=False,
        rcode=None,
        ra=False,
        aa=False,
        answer_count=0
    )

    authoritative = make_result(
        responded=False,
        rcode=None,
        ra=False,
        aa=False,
        answer_count=0
    )

    result = classify_dns_server(
        recursive,
        authoritative
    )

    assert result == "INCONCLUSIVE"


# ============================================================
# TEST 5: SERVFAIL
# ============================================================

def test_servfail_is_inconclusive():

    recursive = make_result(
        responded=True,
        rcode="SERVFAIL",
        ra=True,
        aa=False,
        answer_count=0
    )

    authoritative = make_result(
        responded=True,
        rcode="SERVFAIL",
        ra=False,
        aa=False,
        answer_count=0
    )

    result = classify_dns_server(
        recursive,
        authoritative
    )

    assert result == "INCONCLUSIVE"


# ============================================================
# TEST 6: RA FLAG WITHOUT SUCCESSFUL RESOLUTION
# ============================================================

def test_ra_flag_alone_does_not_mean_recursive():

    recursive = make_result(
        responded=True,
        rcode="SERVFAIL",
        ra=True,
        aa=False,
        answer_count=0
    )

    authoritative = make_result(
        responded=True,
        rcode="REFUSED",
        ra=False,
        aa=False,
        answer_count=0
    )

    result = classify_dns_server(
        recursive,
        authoritative
    )

    assert result == "INCONCLUSIVE"


# ============================================================
# TEST 7: AUTHORITATIVE ANSWER WITHOUT RECURSION EVIDENCE
# ============================================================

def test_authoritative_with_ambiguous_recursive_result():

    recursive = make_result(
        responded=True,
        rcode="SERVFAIL",
        ra=False,
        aa=False,
        answer_count=0
    )

    authoritative = make_result(
        responded=True,
        rcode="NOERROR",
        ra=False,
        aa=True,
        answer_count=1
    )

    result = classify_dns_server(
        recursive,
        authoritative
    )

    assert result == "INCONCLUSIVE"


# ============================================================
# TEST 8: NOERROR WITHOUT ANSWERS
# ============================================================

def test_noerror_without_answers_is_not_recursive():

    recursive = make_result(
        responded=True,
        rcode="NOERROR",
        ra=True,
        aa=False,
        answer_count=0
    )

    authoritative = make_result(
        responded=True,
        rcode="REFUSED",
        ra=False,
        aa=False,
        answer_count=0
    )

    result = classify_dns_server(
        recursive,
        authoritative
    )

    assert result == "INCONCLUSIVE"
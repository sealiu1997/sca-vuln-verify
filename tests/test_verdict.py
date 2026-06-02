from sca_vuln_verify.modules.verdict import suggest_verdict


def test_kev_and_high_epss_suggests_exploitable():
    verdict = suggest_verdict(
        {
            "version_match": True,
            "kev_listed": True,
            "epss_score": 0.95,
        }
    )

    assert verdict["status"] == "exploitable"
    assert verdict["confidence"] == "high"
    assert verdict["requires_human_review"] is False


def test_version_not_match_suggests_not_exploitable():
    verdict = suggest_verdict({"version_match": False})

    assert verdict["status"] == "not_exploitable"
    assert verdict["confidence"] == "high"


def test_missing_key_dimension_requires_human_review():
    verdict = suggest_verdict({"version_match": None})

    assert verdict["status"] == "inconclusive"
    assert verdict["confidence"] == "low"
    assert verdict["requires_human_review"] is True


def test_api_error_marks_review_and_reduces_high_confidence():
    verdict = suggest_verdict(
        {
            "version_match": True,
            "kev_listed": True,
            "epss_score": 0.99,
            "evidence": [{"type": "api_error"}],
        }
    )

    assert verdict["status"] == "exploitable"
    assert verdict["confidence"] == "medium"
    assert verdict["requires_human_review"] is True


def test_poc_direct_used_suggests_likely_exploitable_high():
    verdict = suggest_verdict(
        {
            "version_match": True,
            "poc_enable": True,
            "is_direct": True,
            "use_status": "使用",
        }
    )

    assert verdict["status"] == "likely_exploitable"
    assert verdict["confidence"] == "high"


def test_poc_transitive_suggests_likely_exploitable_medium():
    verdict = suggest_verdict(
        {
            "version_match": True,
            "poc_enable": True,
            "is_direct": False,
        }
    )

    assert verdict["status"] == "likely_exploitable"
    assert verdict["confidence"] == "medium"


def test_no_poc_direct_suggests_inconclusive_medium():
    verdict = suggest_verdict(
        {
            "version_match": True,
            "poc_enable": False,
            "is_direct": True,
        }
    )

    assert verdict["status"] == "inconclusive"
    assert verdict["confidence"] == "medium"


def test_transitive_unused_suggests_likely_not_exploitable_medium():
    verdict = suggest_verdict(
        {
            "version_match": True,
            "poc_enable": False,
            "is_direct": False,
            "use_status": "未使用",
        }
    )

    assert verdict["status"] == "likely_not_exploitable"
    assert verdict["confidence"] == "medium"

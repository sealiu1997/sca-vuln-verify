from sca_vuln_verify.modules.data_process import compare_versions, match_fix_version


def test_maven_beta_range_matches_affected_version():
    result = compare_versions(
        "2.14.1",
        {
            "start_version": "2.0-beta9",
            "start_open": False,
            "end_version": "2.15.0",
            "end_open": True,
        },
        ecosystem="maven",
    )

    assert result.status == "matched"
    assert result.is_match is True


def test_open_end_boundary_does_not_match_equal_end():
    result = compare_versions(
        "2.15.0",
        {
            "start_version": "2.0-beta9",
            "start_open": False,
            "end_version": "2.15.0",
            "end_open": True,
        },
        ecosystem="maven",
    )

    assert result.status == "not_matched"
    assert result.is_match is False


def test_missing_end_version_means_no_upper_bound():
    result = compare_versions(
        "9.9.9",
        {
            "start_version": "1.0.0",
            "start_open": False,
            "end_version": "",
            "end_open": True,
        },
    )

    assert result.is_match is True


def test_unparseable_version_returns_unknown():
    result = compare_versions("not a version", {"start_version": "1.0.0", "end_version": "2.0.0"})

    assert result.status == "unknown"
    assert result.is_match is None


def test_match_fix_version_returns_nearest_unaffected_upgrade():
    fix_version = match_fix_version(
        "2.14.1",
        ["2.14.1", "2.15.0", "2.16.0", "2.17.0"],
        [
            {
                "start_version": "2.0-beta9",
                "start_open": False,
                "end_version": "2.16.0",
                "end_open": True,
            }
        ],
        ecosystem="maven",
    )

    assert fix_version == "2.16.0"


def test_match_fix_version_returns_none_when_versions_are_unknown():
    assert match_fix_version("not a version", ["2.0.0"], []) is None

import json
import os
import time

from sca_vuln_verify.adapters.epss_api import EPSS_API_URL
from sca_vuln_verify.adapters.kev_feed import KEV_FEED_URL
from sca_vuln_verify.modules.external_intel import check_kev, query_epss


def test_epss_response_is_normalized(httpx_mock, tmp_path):
    httpx_mock.add_response(
        method="GET",
        url=f"{EPSS_API_URL}?cve=CVE-2021-44228",
        json={
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.975",
                    "percentile": "0.999",
                    "date": "2026-05-31",
                }
            ]
        },
    )

    result = query_epss("CVE-2021-44228", cache_dir=tmp_path)

    assert result["status"] == "known"
    assert result["score"] == 0.975
    assert result["percentile"] == 0.999


def test_missing_cve_does_not_call_external_api(httpx_mock, tmp_path):
    result = query_epss("", cache_dir=tmp_path)

    assert result["status"] == "unknown"
    assert httpx_mock.get_requests() == []


def test_kev_listed_cve_is_normalized(httpx_mock, tmp_path):
    httpx_mock.add_response(
        method="GET",
        url=KEV_FEED_URL,
        json={
            "catalogVersion": "2026.06.01",
            "dateReleased": "2026-06-01T00:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                    "requiredAction": "Apply updates.",
                }
            ],
        },
    )

    result = check_kev("CVE-2021-44228", cache_dir=tmp_path)

    assert result["status"] == "known"
    assert result["kev_listed"] is True
    assert result["due_date"] == "2021-12-24"


def test_kev_cache_hit_avoids_second_network_call(httpx_mock, tmp_path):
    httpx_mock.add_response(
        method="GET",
        url=KEV_FEED_URL,
        json={"vulnerabilities": [{"cveID": "CVE-2021-44228"}]},
    )

    first = check_kev("CVE-2021-44228", cache_dir=tmp_path)
    second = check_kev("CVE-2021-44228", cache_dir=tmp_path)

    assert first["kev_listed"] is True
    assert second["cache_status"] == "cache"
    assert len(httpx_mock.get_requests()) == 1


def test_epss_stale_cache_is_used_when_network_fails(httpx_mock, tmp_path):
    httpx_mock.add_response(
        method="GET",
        url=f"{EPSS_API_URL}?cve=CVE-2021-44228",
        status_code=503,
        text="temporarily unavailable",
    )
    cache_path = tmp_path / "epss-CVE-2021-44228.json"
    cache_path.write_text(
        json.dumps(
            {
                "data": [
                    {
                        "cve": "CVE-2021-44228",
                        "epss": "0.5",
                        "percentile": "0.8",
                        "date": "2026-05-30",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    old_time = time.time() - 48 * 60 * 60
    os.utime(cache_path, (old_time, old_time))

    result = query_epss("CVE-2021-44228", cache_dir=tmp_path, ttl_seconds=1)

    assert result["cache_status"] == "stale_cache"
    assert result["score"] == 0.5
    assert len(httpx_mock.get_requests()) == 1

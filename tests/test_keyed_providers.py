"""Unit tests for the keyed Tier 1 providers (VT/AbuseIPDB/OTX/Censys)."""

from __future__ import annotations

import httpx
import pytest

from core.intel.base import IOCQuery
from core.intel.keyed import (
    AbuseIpdbProvider,
    CensysProvider,
    OtxProvider,
    VirusTotalProvider,
)


def _c(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_virustotal_malicious_and_score() -> None:
    body = {"data": {"attributes": {"last_analysis_stats":
            {"malicious": 6, "suspicious": 1, "harmless": 60, "undetected": 3}}}}
    p = VirusTotalProvider(api_key="k", http_client=_c(lambda r: httpx.Response(200, json=body)))
    res = p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4"))
    assert res.verdict == "malicious"
    assert res.score == pytest.approx(7 / 70)
    p.close()


def test_virustotal_404_unknown() -> None:
    p = VirusTotalProvider(api_key="k", http_client=_c(lambda r: httpx.Response(404, json={})))
    assert p.query(IOCQuery(value="x.com", ioc_type="domain")).verdict == "unknown"
    p.close()


def test_abuseipdb_confidence_bands() -> None:
    def mk(score):
        return AbuseIpdbProvider(api_key="k",
            http_client=_c(lambda r: httpx.Response(200, json={"data": {"abuseConfidenceScore": score}})))
    assert mk(90).query(IOCQuery(value="1.2.3.4", ioc_type="ipv4")).verdict == "malicious"
    assert mk(40).query(IOCQuery(value="1.2.3.4", ioc_type="ipv4")).verdict == "suspicious"
    assert mk(0).query(IOCQuery(value="1.2.3.4", ioc_type="ipv4")).verdict == "benign"


def test_otx_pulse_count() -> None:
    def mk(count):
        return OtxProvider(api_key="k",
            http_client=_c(lambda r: httpx.Response(200, json={"pulse_info": {"count": count}})))
    assert mk(5).query(IOCQuery(value="1.2.3.4", ioc_type="ipv4")).verdict == "malicious"
    assert mk(2).query(IOCQuery(value="1.2.3.4", ioc_type="ipv4")).verdict == "suspicious"
    assert mk(0).query(IOCQuery(value="1.2.3.4", ioc_type="ipv4")).verdict == "unknown"


def test_censys_labels_and_services() -> None:
    mal = {"result": {"labels": ["C2"], "services": [{"port": 443}]}}
    p = CensysProvider(api_key="k", http_client=_c(lambda r: httpx.Response(200, json=mal)))
    assert p.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4")).verdict == "malicious"
    clean = {"result": {"labels": [], "services": [{"port": 22}]}}
    p2 = CensysProvider(api_key="k", http_client=_c(lambda r: httpx.Response(200, json=clean)))
    assert p2.query(IOCQuery(value="1.2.3.4", ioc_type="ipv4")).verdict == "benign"


def test_virustotal_supported_types() -> None:
    p = VirusTotalProvider(api_key="k", http_client=_c(lambda r: httpx.Response(404)))
    assert p.supports("sha256") and p.supports("domain") and not p.supports("email")
    p.close()

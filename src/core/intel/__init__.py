"""
Tier 1 — External threat-intel adapters.

Providers feed a single `IOCAggregator` that folds N answers into one
`IOCVerdict`. Keyless: apt_watch, dshield, shodan_internetdb, firehol, ipsum,
stevenblack. Keyed: virustotal, abuseipdb, otx, censys. Feed search verbs
(threatfox, tweetfeed) live in `feeds.py`.

References:
- docs/architecture/shared-brain.md
- docs/design/tier1-intel-lookup-pattern.md
"""

from __future__ import annotations

from core.intel.aggregator import (
    DEFAULT_VERDICT_PRECEDENCE,
    IOCAggregator,
    aggregate_results,
)
from core.intel.apt_watch import DEFAULT_BASE_URL, AptWatchProvider
from core.intel.base import (
    IOCProvider,
    IOCProviderError,
    IOCQuery,
    IOCTimeoutError,
    IOCTransportError,
    IOCUnsupportedError,
)
from core.intel.blocklist import (
    BlocklistProviderBase,
    FireholProvider,
    IpsumProvider,
    StevenBlackProvider,
)
from core.intel.dshield import DShieldProvider
from core.intel.feeds import search_threatfox, search_tweetfeed
from core.intel.http_provider import HTTPIOCProviderBase
from core.intel.keyed import (
    AbuseIpdbProvider,
    CensysProvider,
    OtxProvider,
    VirusTotalProvider,
)
from core.intel.providers import build_aggregator
from core.intel.shodan_internetdb import ShodanInternetDbProvider
from core.intel.stub import StubIOCProvider

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_VERDICT_PRECEDENCE",
    "AbuseIpdbProvider",
    "AptWatchProvider",
    "BlocklistProviderBase",
    "CensysProvider",
    "DShieldProvider",
    "FireholProvider",
    "HTTPIOCProviderBase",
    "IOCAggregator",
    "IOCProvider",
    "IOCProviderError",
    "IOCQuery",
    "IOCTimeoutError",
    "IOCTransportError",
    "IOCUnsupportedError",
    "IpsumProvider",
    "OtxProvider",
    "ShodanInternetDbProvider",
    "StevenBlackProvider",
    "StubIOCProvider",
    "VirusTotalProvider",
    "aggregate_results",
    "build_aggregator",
    "search_threatfox",
    "search_tweetfeed",
]

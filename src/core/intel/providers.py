"""
Provider factory — builds a configured `IOCAggregator` from `IntelConfig`.

Tier 1 is opt-in: a provider is only registered when its config section is
`enabled` (and, for keyed providers, when the env var named by `api_key_env`
is actually set). Keyless providers need no secret.

Credentials never live in config files — config only names the *env var*
(`api_key_env`); this factory reads the value from the process environment at
build time. This keeps secrets out of the repo and the audit log.
"""

from __future__ import annotations

import os

import httpx

from core.config import APTWatcherConfig, IntelProviderConfig
from core.intel.aggregator import IOCAggregator
from core.intel.apt_watch import DEFAULT_BASE_URL, AptWatchProvider
from core.intel.base import IOCProvider
from core.intel.blocklist import FireholProvider, IpsumProvider, StevenBlackProvider
from core.intel.dshield import DEFAULT_BASE_URL as DSHIELD_BASE_URL
from core.intel.dshield import DShieldProvider
from core.intel.keyed import (
    ABUSEIPDB_KEY_ENV,
    CENSYS_KEY_ENV,
    OTX_KEY_ENV,
    VIRUSTOTAL_KEY_ENV,
    AbuseIpdbProvider,
    CensysProvider,
    OtxProvider,
    VirusTotalProvider,
)
from core.intel.shodan_internetdb import DEFAULT_BASE_URL as SHODAN_BASE_URL
from core.intel.shodan_internetdb import ShodanInternetDbProvider


def _key_for(section: IntelProviderConfig, default_env: str) -> str | None:
    """Resolve a keyed provider's API key from the env var it names."""
    return os.environ.get(section.api_key_env or default_env) or None


def build_aggregator(
    cfg: APTWatcherConfig, *, http_client: httpx.Client | None = None
) -> IOCAggregator:
    """Construct an aggregator with every enabled, satisfiable provider.

    Keyless providers register when `enabled`. Keyed providers register only
    when `enabled` AND their API key env var is set. Returns an empty
    aggregator (uniform `unknown`) when Tier 1 is off.
    """
    agg = IOCAggregator()
    if not getattr(cfg.tiers, "tier_1", False):
        return agg

    intel = cfg.intel
    providers: list[IOCProvider] = []

    # --- Keyless ---------------------------------------------------------
    aw = intel.apt_watch
    if aw.enabled:
        providers.append(AptWatchProvider(base_url=aw.base_url or DEFAULT_BASE_URL,
                                          timeout_s=float(aw.timeout_seconds), http_client=http_client))
    ds = intel.dshield
    if ds.enabled:
        providers.append(DShieldProvider(base_url=ds.base_url or DSHIELD_BASE_URL,
                                         timeout_s=float(ds.timeout_seconds), http_client=http_client))
    si = intel.shodan_internetdb
    if si.enabled:
        providers.append(ShodanInternetDbProvider(base_url=si.base_url or SHODAN_BASE_URL,
                                                  timeout_s=float(si.timeout_seconds), http_client=http_client))
    fh = intel.firehol
    if fh.enabled:
        providers.append(FireholProvider(list_url=fh.base_url or None,
                                         timeout_s=float(fh.timeout_seconds), http_client=http_client))
    ips = intel.ipsum
    if ips.enabled:
        providers.append(IpsumProvider(list_url=ips.base_url or None,
                                       timeout_s=float(ips.timeout_seconds), http_client=http_client))
    sb = intel.stevenblack
    if sb.enabled:
        providers.append(StevenBlackProvider(list_url=sb.base_url or None,
                                             timeout_s=float(sb.timeout_seconds), http_client=http_client))

    # --- Keyed (only when the key env var is set) ------------------------
    vt = intel.virustotal
    if vt.enabled and (k := _key_for(vt, VIRUSTOTAL_KEY_ENV)):
        providers.append(VirusTotalProvider(api_key=k, timeout_s=float(vt.timeout_seconds),
                                            http_client=http_client))
    ab = intel.abuseipdb
    if ab.enabled and (k := _key_for(ab, ABUSEIPDB_KEY_ENV)):
        providers.append(AbuseIpdbProvider(api_key=k, timeout_s=float(ab.timeout_seconds),
                                           http_client=http_client))
    ot = intel.otx
    if ot.enabled and (k := _key_for(ot, OTX_KEY_ENV)):
        providers.append(OtxProvider(api_key=k, timeout_s=float(ot.timeout_seconds),
                                     http_client=http_client))
    ce = intel.censys
    if ce.enabled and (k := _key_for(ce, CENSYS_KEY_ENV)):
        providers.append(CensysProvider(api_key=k, timeout_s=float(ce.timeout_seconds),
                                        http_client=http_client))

    for p in providers:
        agg.register(p)
    return agg

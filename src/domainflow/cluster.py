"""Group findings into campaigns by shared, discriminating infrastructure.

The goal: a coordinated wave of lookalikes should read as **one** thing (and be
actioned as a batch), not N scattered one-offs.

The trap is over-clustering. Phishing kits overwhelmingly reuse a handful of
bulk registrars, Let's Encrypt, and shared CDNs — joining on those would merge
everything into one meaningless blob. So clustering only joins on *discriminating*
pivots (resolved IP, WHOIS registrant org, non-bulk nameserver) and:

1. drops pivot values on hard noise lists (bulk NS/CDN, privacy-proxy registrants),
2. drops any pivot value shared by an implausibly large share of the population
   (that's infrastructure, not a campaign),

then merges the survivors with union-find. Registrar and cert issuer ride along
as descriptive context but are **not** join keys (too generic on their own).

Example::

    from domainflow import cluster_campaigns
    campaigns = cluster_campaigns(findings)   # findings: list[Finding] or list[dict]
    for c in campaigns:
        print(c.size, [p.value for p in c.pivots], c.domains)
"""

from __future__ import annotations

from typing import Any, Dict, List, Union

from .models import Campaign, Finding, Pivot

# Registrant orgs that mean "privacy-protected" — no real attribution.
_PRIVACY_REGISTRANTS = (
    "redacted", "privacy", "whoisguard", "domains by proxy", "perfect privacy",
    "withheld", "data protected", "not disclosed", "private", "contact privacy",
    "identity protection", "domain protection", "gdpr", "registration private",
    "statutory masking",
)
# Nameserver substrings that mark bulk/parking/CDN providers — shared by huge
# numbers of unrelated domains, so useless as a campaign join key.
_BULK_NS_SUBSTRINGS = (
    "cloudflare", "domaincontrol", "godaddy", "namecheap", "registrar-servers",
    "sedoparking", "bodis", "parkingcrew", "above.com", "dan.com", "uniregistry",
    "amazonaws", "awsdns", "azure-dns", "googledomains", "google.com", "ns.cloudns",
    "hostinger", "wixdns", "squarespace", "shopify", "fastly", "akamai",
    "name-services", "registrar.eu",
)
# Shared/CDN/parking sentinels that connect unrelated domains — never a join key.
_NOISE_IPS = {"127.0.0.1", "0.0.0.0", "::1", ""}

# A pivot shared by more than this fraction of the population is infrastructure,
# not a campaign (e.g. one IP fronting every parked lookalike).
_MAX_PIVOT_SHARE = 0.5
_MAX_PIVOT_DOMAINS = 25  # absolute ceiling regardless of share
# The share-based cap only makes sense once the population is big enough that
# "shared by half" is meaningful. Below this, a real campaign can legitimately
# span most of the findings, so only the absolute ceiling applies.
_MIN_POP_FOR_SHARE = 8


def _is_privacy_registrant(val: str) -> bool:
    v = val.lower()
    return any(tok in v for tok in _PRIVACY_REGISTRANTS)


def _is_bulk_ns(val: str) -> bool:
    v = val.lower()
    return any(tok in v for tok in _BULK_NS_SUBSTRINGS)


class _UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _coerce(findings: List[Union[Finding, Dict[str, Any]]]) -> List[Finding]:
    out = []
    for f in findings:
        out.append(f if isinstance(f, Finding) else Finding.from_dict(f))
    return out


def cluster_campaigns(
    findings: List[Union[Finding, Dict[str, Any]]],
    max_pivot_share: float = _MAX_PIVOT_SHARE,
    max_pivot_domains: int = _MAX_PIVOT_DOMAINS,
) -> List[Campaign]:
    """Cluster findings into campaigns by shared infrastructure.

    Args:
        findings: a list of :class:`~domainflow.models.Finding` (or plain dicts,
            which are coerced via :meth:`Finding.from_dict`).
        max_pivot_share: a pivot value shared by more than this fraction of all
            findings is treated as infrastructure and ignored as a join key.
        max_pivot_domains: absolute ceiling on how many domains a pivot may bind
            before it's treated as infrastructure.

    Returns:
        Campaigns of >= 2 domains, sorted active-first then largest-first. Each
        carries the pivots that bound it, the brands/registrars involved, and a
        contained count.
    """
    rows = _coerce(findings)
    by_domain: Dict[str, Finding] = {}
    buckets: Dict[str, Dict[str, set]] = {"ip": {}, "registrant": {}, "nameserver": {}}

    for f in rows:
        dom = (f.domain or "").strip().lower()
        if not dom:
            continue
        by_domain[dom] = f
        for ip in f.ip_addresses:
            ip = str(ip).strip().lower()
            if ip and ip not in _NOISE_IPS:
                buckets["ip"].setdefault(ip, set()).add(dom)
        org = (f.registrant_org or "").strip().lower()
        if org and not _is_privacy_registrant(org):
            buckets["registrant"].setdefault(org, set()).add(dom)
        for ns in f.nameservers:
            ns = str(ns).strip().lower().rstrip(".")
            if ns and not _is_bulk_ns(ns):
                buckets["nameserver"].setdefault(ns, set()).add(dom)

    total = max(1, len(by_domain))
    if total >= _MIN_POP_FOR_SHARE:
        cap = min(max_pivot_domains, max(2, int(total * max_pivot_share)))
    else:
        cap = max_pivot_domains

    uf = _UnionFind()
    for dom in by_domain:  # seed every domain so singletons exist as their own root
        uf.find(dom)

    # Each non-noise pivot value shared by 2..cap domains is a campaign edge.
    edges: List[tuple] = []  # (ptype, value, [domains])
    for ptype, vmap in buckets.items():
        for value, doms in vmap.items():
            if 2 <= len(doms) <= cap:
                doms_sorted = sorted(doms)
                first = doms_sorted[0]
                for other in doms_sorted[1:]:
                    uf.union(first, other)
                edges.append((ptype, value, doms_sorted))

    # Connected components of size >= 2.
    comps: Dict[str, List[str]] = {}
    for dom in by_domain:
        comps.setdefault(uf.find(dom), []).append(dom)

    campaigns: List[Campaign] = []
    for doms in comps.values():
        if len(doms) < 2:
            continue
        domset = set(doms)
        pivots = []
        for ptype, value, edoms in edges:
            shared = domset.intersection(edoms)
            if len(shared) >= 2:
                pivots.append(Pivot(type=ptype, value=value, count=len(shared)))
        pivots.sort(key=lambda p: p.count, reverse=True)

        members = [by_domain[d] for d in doms]
        brands = sorted({(m.brand or "Unattributed") for m in members})
        registrars = sorted({m.registrar.strip() for m in members if (m.registrar or "").strip()})
        any_active = any(m.active for m in members)
        contained = sum(1 for m in members if m.contained)
        campaigns.append(Campaign(
            id=0, domains=sorted(doms), pivots=pivots, brands=brands,
            registrars=registrars, any_active=any_active, contained=contained,
        ))

    # Biggest + active-first: what to look at first.
    campaigns.sort(key=lambda c: (c.any_active, c.size), reverse=True)
    for i, c in enumerate(campaigns, 1):
        c.id = i
    return campaigns

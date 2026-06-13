"""Lightweight, dependency-free data shapes shared across the layers.

These are plain dataclasses with ``to_dict``/``from_dict`` so they round-trip
to JSON and play nicely with whatever storage a caller already has — domainflow
never imposes a database.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class Lookalike:
    """A candidate impersonation domain produced by :mod:`domainflow.discover`."""

    domain: str
    fuzzer: str = "unknown"  # which generator produced it (homoglyph, tld-swap, …)
    target: Optional[str] = None  # the legitimate domain it imitates

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A domain under investigation, plus the infrastructure pivots that make it
    clusterable. Every field beyond ``domain`` is optional — populate whatever
    your discovery/enrichment pipeline collected.
    """

    domain: str
    brand: Optional[str] = None
    source: Optional[str] = None       # lookalike | ct | whois | manual …
    status: Optional[str] = None       # caller-defined disposition
    # Infrastructure pivots — the clustering signal.
    registrar: Optional[str] = None
    registrant_org: Optional[str] = None
    ip_addresses: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    cert_issuer: Optional[str] = None
    # Optional triage signal used to prioritise campaigns.
    active: bool = False               # confirmed live/weaponized
    contained: bool = False            # blocked / takedown raised

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        """Build a Finding from a loose dict, tolerating extra/missing keys and
        scalar-vs-list shapes for the address fields."""
        def _list(v: Any) -> List[str]:
            if v is None:
                return []
            if isinstance(v, str):
                return [v]
            return [str(x) for x in v]

        return cls(
            domain=str(d.get("domain") or "").strip().lower(),
            brand=d.get("brand"),
            source=d.get("source"),
            status=d.get("status"),
            registrar=d.get("registrar"),
            registrant_org=d.get("registrant_org") or d.get("registrant"),
            ip_addresses=_list(d.get("ip_addresses") or d.get("ips") or d.get("dns_a")),
            nameservers=_list(d.get("nameservers") or d.get("name_servers") or d.get("dns_ns")),
            cert_issuer=d.get("cert_issuer") or d.get("issuer"),
            active=bool(d.get("active") or d.get("weaponization_active")),
            contained=bool(d.get("contained") or d.get("xsoar_id") or d.get("takedown_at")),
        )


@dataclass
class Pivot:
    """The shared attribute that bound a campaign together."""

    type: str   # ip | registrant | nameserver
    value: str
    count: int  # how many of the campaign's domains share it

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Campaign:
    """A connected component of findings that share infrastructure — usually a
    single actor's coordinated wave of impersonations."""

    id: int
    domains: List[str]
    pivots: List[Pivot] = field(default_factory=list)
    brands: List[str] = field(default_factory=list)
    registrars: List[str] = field(default_factory=list)
    any_active: bool = False
    contained: int = 0

    @property
    def size(self) -> int:
        return len(self.domains)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["size"] = self.size
        return d

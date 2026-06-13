"""WHOIS snapshot + change detection.

A snapshot captures the registration facts that matter for impersonation
tracking — registrar, registrant org, nameservers, creation/expiry — in a
normalised, JSON-friendly shape. Diffing two snapshots surfaces the moves that
matter: a brand-new registration, a registrant/org change (ownership move), or
a nameserver change (infrastructure move).

The snapshot's ``registrar`` / ``registrant_org`` / ``name_servers`` map
directly onto :class:`domainflow.models.Finding`'s clustering pivots.

Requires the ``whois`` extra (``pip install domainflow[whois]``).

Example::

    from domainflow.monitor import whois
    snap = whois.snapshot("acme-login.com")
    changes = whois.diff(previous_snap, snap)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _whois_lib():
    try:
        import whois as _w  # python-whois
        return _w
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "WHOIS snapshot needs the 'whois' extra: pip install domainflow[whois]"
        ) from e


def _to_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, list):
        val = val[0] if val else None
    return str(val).strip() if val is not None else None


def _iso(val: Any) -> Optional[str]:
    if isinstance(val, list):
        val = val[0] if val else None
    try:
        return val.isoformat()  # datetime
    except AttributeError:
        return _to_str(val)


def snapshot(domain: str) -> Dict[str, Any]:
    """Look up ``domain`` and return a normalised WHOIS snapshot.

    Returns a dict with ``domain``, ``registrar``, ``registrant_org``,
    ``registrant_country``, ``name_servers`` (sorted, lowercased), ``created``,
    ``expires``, and ``registered`` (False when the domain is unregistered).
    Never raises on lookup failure — it returns ``{"domain", "error"}``.
    """
    domain = (domain or "").strip().lower()
    w = _whois_lib()
    try:
        r = w.whois(domain)
    except Exception as e:  # python-whois raises a custom error for unregistered
        msg = str(e).lower()
        registered = not ("no match" in msg or "not found" in msg)
        return {"domain": domain, "registered": registered, "error": type(e).__name__}

    ns = r.name_servers
    if isinstance(ns, str):
        ns = [ns]
    name_servers = sorted({n.lower().rstrip(".") for n in (ns or []) if n}) if ns else []

    return {
        "domain": domain,
        "registered": bool(r.registrar or r.creation_date or name_servers),
        "registrar": _to_str(r.registrar),
        "registrant_org": _to_str(getattr(r, "org", None)),
        "registrant_country": _to_str(getattr(r, "country", None)),
        "name_servers": name_servers,
        "created": _iso(r.creation_date),
        "expires": _iso(r.expiration_date),
        "error": None,
    }


# Fields whose change is worth flagging, with a human label + severity.
_WATCHED = (
    ("registrar", "registrar", "medium"),
    ("registrant_org", "registrant org", "high"),
    ("registrant_country", "registrant country", "medium"),
)


def diff(previous: Optional[Dict[str, Any]], current: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compare two snapshots and return a list of change records.

    Each change is ``{field, previous, current, severity}``. A first-ever
    observation (``previous`` is None/empty) of a registered domain is reported
    as a ``registration`` change (severity ``high``). Nameserver set changes are
    reported as ``name_servers`` (severity ``high`` — infrastructure move).
    """
    changes: List[Dict[str, Any]] = []
    if not previous:
        if current.get("registered"):
            changes.append({"field": "registration", "previous": None,
                            "current": current.get("registrar"), "severity": "high"})
        return changes

    for key, label, severity in _WATCHED:
        if previous.get(key) != current.get(key):
            changes.append({"field": label, "previous": previous.get(key),
                            "current": current.get(key), "severity": severity})

    prev_ns = set(previous.get("name_servers") or [])
    curr_ns = set(current.get("name_servers") or [])
    if prev_ns != curr_ns:
        changes.append({"field": "name_servers", "previous": sorted(prev_ns),
                        "current": sorted(curr_ns), "severity": "high"})
    return changes

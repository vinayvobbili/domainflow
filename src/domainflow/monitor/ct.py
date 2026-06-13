"""Certificate Transparency search via crt.sh.

A newly-issued TLS certificate containing a brand keyword is one of the
earliest, strongest signals that an impersonation domain has been stood up —
often before it's weaponized. This queries crt.sh's public JSON endpoint.

Requires the ``ct`` extra (``pip install domainflow[ct]``) for ``requests``.

Example::

    from domainflow.monitor import ct
    for c in ct.search_certs("acme"):
        print(c["common_name"], c["issuer"], c["not_before"])
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

CRTSH_URL = "https://crt.sh/"
_DEFAULT_TIMEOUT = 30


def _requests():
    try:
        import requests  # noqa: F401
        return requests
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "Certificate Transparency search needs the 'ct' extra: "
            "pip install domainflow[ct]"
        ) from e


def search_certs(
    query: str,
    timeout: int = _DEFAULT_TIMEOUT,
    exclude_expired: bool = False,
    session: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Search crt.sh for certificates matching ``query``.

    Args:
        query: a domain or identity substring, e.g. ``"acme"`` or ``"%.acme.com"``
            (crt.sh supports ``%`` wildcards in the identity).
        timeout: HTTP timeout in seconds.
        exclude_expired: ask crt.sh to drop already-expired certs.
        session: an optional ``requests.Session`` to reuse.

    Returns:
        A de-duplicated list of certificate records, each with ``common_name``,
        ``name_value`` (the SAN list, newline-joined as crt.sh returns it),
        ``issuer``, ``not_before``, ``not_after``, and ``serial``.
    """
    requests = _requests()
    params = {"q": query, "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"
    http = session or requests
    resp = http.get(CRTSH_URL, params=params, timeout=timeout,
                    headers={"User-Agent": "domainflow/0.1"})
    resp.raise_for_status()
    # crt.sh occasionally returns concatenated JSON objects; be tolerant.
    text = resp.text.strip()
    try:
        rows = resp.json()
    except (ValueError, json.JSONDecodeError):
        rows = json.loads("[" + text.replace("}\n{", "},\n{") + "]")

    seen = set()
    out: List[Dict[str, Any]] = []
    for r in rows:
        serial = r.get("serial_number")
        key = (serial, r.get("name_value"))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "common_name": r.get("common_name"),
            "name_value": r.get("name_value"),
            "issuer": r.get("issuer_name"),
            "not_before": r.get("not_before"),
            "not_after": r.get("not_after"),
            "serial": serial,
        })
    return out


def discovered_domains(query: str, **kwargs: Any) -> List[str]:
    """Flatten crt.sh results into a sorted, de-duplicated domain list.

    Pulls every name from the SAN (``name_value``) field, drops wildcards' ``*.``
    prefix, and lowercases. Convenience wrapper over :func:`search_certs`.
    """
    domains = set()
    for cert in search_certs(query, **kwargs):
        for name in (cert.get("name_value") or "").splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and "." in name:
                domains.add(name)
    return sorted(domains)

"""Turn "a lookalike exists" into "is it weaponized?".

Gathers hard signals from a suspect domain — is the page live, does it have a
login/password form, does the brand name appear, is it mail-capable
(MX/SPF/DMARC → BEC/credential-harvest) or just parked — and turns them into a
risk tier:

- **P1** — live credential-harvest / login clone (act now)
- **P2** — stood-up impersonation infra (mail-capable or clone, not yet confirmed)
- **P3** — registered/parked lookalike, not yet weaponized
- **P4** — benign / unreachable / unrelated

A deterministic heuristic produces the tier offline. For a sharper verdict, pass
``llm=`` — any callable taking the facts prompt and returning a dict — and the
signals are handed to your model (bring-your-own-LLM, no vendor lock-in). A
ready-made OpenAI-compatible caller is provided as :func:`openai_verdict`.

The tier is *point-in-time*. To catch the dormant→live flip across scans — a
lookalike that sat parked for weeks and then suddenly stood up, the strongest
weaponization tell — diff two scores with :func:`transition`.

Requires the ``score`` extra (``pip install domainflow[score]``) for the page
fetch + DNS lookups.

Example::

    from domainflow import score
    result = score.score("acme-login.com", brand="acme")
    print(result["tier"], result["signals"]["page"]["has_password_input"])
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Optional

_FETCH_TIMEOUT = 6
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
_PASSWORD_INPUT_RE = re.compile(r"""<input[^>]+type=["']?password""", re.I)
_FORM_RE = re.compile(r"<form\b", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_PAGE_TEXT_BUDGET = 2500


def _requests():
    try:
        import requests  # noqa: F401
        return requests
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "Scoring needs the 'score' extra: pip install domainflow[score]"
        ) from e


def _strip_text(html: str) -> str:
    """Crude visible-text extraction (no bs4 dependency)."""
    html = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)
    text = _TAG_RE.sub(" ", html)
    return re.sub(r"\s+", " ", text).strip()[:_PAGE_TEXT_BUDGET]


def _fetch_page(domain: str, timeout: int, verify: bool) -> tuple:
    requests = _requests()
    sig: Dict[str, Any] = {
        "reachable": False, "status_code": None, "final_url": None,
        "redirected_offsite": False, "has_form": False, "has_password_input": False,
        "title": None, "content_length": 0, "error": None,
    }
    page_text = ""
    headers = {"User-Agent": _UA, "Accept": "text/html,application/xhtml+xml"}
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=timeout,
                                allow_redirects=True, headers=headers, verify=verify)
        except Exception as e:
            sig["error"] = type(e).__name__
            continue
        body = resp.text or ""
        sig.update({
            "reachable": True, "status_code": resp.status_code, "final_url": resp.url,
            "content_length": len(body), "has_form": bool(_FORM_RE.search(body)),
            "has_password_input": bool(_PASSWORD_INPUT_RE.search(body)), "error": None,
        })
        try:
            final_host = resp.url.split("://", 1)[-1].split("/", 1)[0].lower()
            sig["redirected_offsite"] = domain not in final_host
        except Exception:
            pass
        m = _TITLE_RE.search(body)
        if m:
            sig["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:160]
        page_text = _strip_text(body)
        break
    return sig, page_text


def _dns_mail_signals(domain: str) -> Dict[str, Any]:
    """MX / SPF / DMARC presence. Best-effort; dnspython optional."""
    out = {"has_mx": False, "mx_hosts": [], "has_spf": False, "has_dmarc": False, "error": None}
    try:
        import dns.resolver
    except ImportError:
        out["error"] = "dnspython_unavailable"
        return out
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = 4.0
    try:
        answers = resolver.resolve(domain, "MX")
        out["has_mx"] = True
        out["mx_hosts"] = [str(r.exchange).rstrip(".") for r in answers][:5]
    except Exception:
        pass
    for name, flag, token in ((domain, "has_spf", "v=spf1"), (f"_dmarc.{domain}", "has_dmarc", "v=dmarc1")):
        try:
            for r in resolver.resolve(name, "TXT"):
                txt = b"".join(r.strings).decode("utf-8", "ignore") if hasattr(r, "strings") else str(r)
                if token in txt.lower():
                    out[flag] = True
        except Exception:
            pass
    return out


def gather_signals(domain: str, brand: Optional[str] = None, timeout: int = _FETCH_TIMEOUT,
                   verify_tls: bool = True) -> Dict[str, Any]:
    """Collect page + mail signals for a domain. Read-only; takes no action."""
    domain = (domain or "").strip().lower()
    page_sig, page_text = _fetch_page(domain, timeout, verify_tls)
    dns_sig = _dns_mail_signals(domain)
    brand_in_page = None
    if brand and page_text:
        brand_in_page = brand.lower().replace(" ", "") in page_text.lower().replace(" ", "")
    return {
        "domain": domain, "brand": brand, "page": page_sig, "dns": dns_sig,
        "brand_in_page": brand_in_page, "page_text_excerpt": page_text,
    }


def heuristic_tier(signals: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic, offline risk tier from gathered signals.

    Returns ``{tier, is_active_phishing, rationale}``. Conservative: an
    unreachable domain is P4 (registered but not stood up), not escalated.
    """
    p, d = signals.get("page") or {}, signals.get("dns") or {}
    brand_in_page = signals.get("brand_in_page")
    reachable = p.get("reachable")
    has_pw = p.get("has_password_input")
    has_form = p.get("has_form")
    mail = d.get("has_mx")

    if reachable and has_pw and (brand_in_page or has_form):
        return {"tier": "P1", "is_active_phishing": True,
                "rationale": "Live page with a password/login form" +
                             (" cloning the brand" if brand_in_page else "") + "."}
    if reachable and (brand_in_page or has_form) or (mail and reachable):
        return {"tier": "P2", "is_active_phishing": False,
                "rationale": "Stood-up impersonation infrastructure "
                             "(reachable clone or mail-capable), not yet confirmed harvesting."}
    if reachable or mail:
        return {"tier": "P3", "is_active_phishing": False,
                "rationale": "Registered and reachable/mail-capable but no impersonation markers — monitor."}
    return {"tier": "P4", "is_active_phishing": False,
            "rationale": "Not reachable and not mail-capable — registered placeholder or benign."}


_TIER_RANK = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
_TIER_ORDER = ["P4", "P3", "P2", "P1"]


def _activity(result: Optional[Dict[str, Any]]) -> tuple:
    """Normalize a :func:`score`/`:func:`heuristic_tier`/`:func:`gather_signals`
    dict to ``(is_live, tier_rank, tier)``. ``is_live`` is True when the domain
    is reachable or mail-capable — i.e. stood up, not dormant.
    """
    if not result:
        return (False, 0, None)
    tier = result.get("tier")
    if not tier:
        v = result.get("verdict")
        if isinstance(v, dict):
            tier = v.get("tier")
    sig = result.get("signals") if isinstance(result.get("signals"), dict) else result
    p = (sig or {}).get("page") or {}
    d = (sig or {}).get("dns") or {}
    is_live = bool(p.get("reachable") or d.get("has_mx"))
    return (is_live, _TIER_RANK.get((tier or "").upper(), 0), (tier or "").upper() or None)


def _bump(tier: Optional[str]) -> Optional[str]:
    """Escalate a tier one notch toward P1 (capped at P1)."""
    if tier not in _TIER_RANK:
        return tier
    i = _TIER_ORDER.index(tier)
    return _TIER_ORDER[min(i + 1, len(_TIER_ORDER) - 1)]


def transition(previous: Optional[Dict[str, Any]], current: Dict[str, Any],
               *, dormant_days: Optional[float] = None) -> Dict[str, Any]:
    """Compare two point-in-time scores of the *same* domain over time and detect
    the dormant→active flip — the strongest weaponization tell there is.

    :func:`score` is point-in-time: it asks "is this domain weaponized *right
    now?*". But a lookalike that sat parked/dormant for weeks and then *suddenly*
    stands up is far more suspicious than a freshly-discovered live domain of the
    same tier — that delayed activation is deliberate, aged infrastructure. This
    function captures that movement and, on a became-active flip, recommends a
    one-notch escalation above the point-in-time tier.

    Args:
        previous: an earlier :func:`score` result, :func:`heuristic_tier` verdict,
            or raw :func:`gather_signals` dict — whatever you stored last scan.
            ``None`` is treated as "never observed live before".
        current: the latest score/verdict/signals dict for the same domain.
        dormant_days: optional age of the dormancy that just ended (e.g. from your
            stored ``first_seen``). Sharpens the rationale; longer = more
            deliberate. Does not change the recommended tier on its own.

    Returns:
        ``{domain, previous_tier, current_tier, recommended_tier, became_active,
        went_dormant, escalated, deescalated, priority_boost, dormant_days,
        rationale}``. When nothing meaningful changed, ``recommended_tier`` equals
        ``current_tier`` and ``priority_boost`` is False.
    """
    prev_live, prev_rank, prev_tier = _activity(previous)
    cur_live, cur_rank, cur_tier = _activity(current)

    became_active = (not prev_live) and cur_live
    went_dormant = prev_live and (not cur_live)
    escalated = cur_rank > prev_rank > 0
    deescalated = 0 < cur_rank < prev_rank

    recommended_tier = cur_tier
    priority_boost = False
    if became_active and cur_tier:
        bumped = _bump(cur_tier)
        if bumped != cur_tier:
            recommended_tier = bumped
            priority_boost = True

    if became_active:
        age = ""
        if dormant_days is not None:
            age = (f" after ~{int(dormant_days)} days dormant"
                   if dormant_days >= 1 else " after a brief dormancy")
        rationale = (
            f"Domain was dormant (parked/unreachable) and just went live{age} — "
            "delayed activation of aged infrastructure is a deliberate weaponization "
            "tell. Escalate above a freshly-stood-up domain of the same tier."
        )
    elif went_dormant:
        rationale = ("Previously live, now dormant (taken down, parked, or rotated "
                     "off). Keep watching — actors recycle aged domains.")
    elif escalated:
        rationale = (f"Weaponization advanced {prev_tier or '?'}→{cur_tier or '?'} "
                     "between observations.")
    elif deescalated:
        rationale = (f"Weaponization receded {prev_tier or '?'}→{cur_tier or '?'} "
                     "between observations.")
    else:
        rationale = "No material change in weaponization state between observations."

    domain = (current.get("domain")
              or ((current.get("signals") or {}).get("domain") if isinstance(current.get("signals"), dict) else None))
    return {
        "domain": domain,
        "previous_tier": prev_tier,
        "current_tier": cur_tier,
        "recommended_tier": recommended_tier,
        "became_active": became_active,
        "went_dormant": went_dormant,
        "escalated": escalated,
        "deescalated": deescalated,
        "priority_boost": priority_boost,
        "dormant_days": dormant_days,
        "rationale": rationale,
    }


def facts_prompt(signals: Dict[str, Any]) -> str:
    """Render gathered signals into a prompt for a bring-your-own-LLM verdict."""
    p, d = signals.get("page") or {}, signals.get("dns") or {}
    lines = [
        f"Domain: {signals.get('domain')}",
        f"Targeted brand: {signals.get('brand') or 'unknown'}",
        f"Page reachable: {p.get('reachable')} (HTTP {p.get('status_code')})",
        f"Final URL after redirects: {p.get('final_url')}",
        f"Redirected off the domain: {p.get('redirected_offsite')}",
        f"Has a form: {p.get('has_form')}; has a password field: {p.get('has_password_input')}",
        f"Page title: {p.get('title')!r}",
        f"Brand name appears in page text: {signals.get('brand_in_page')}",
        f"Mail-capable (MX): {d.get('has_mx')} {d.get('mx_hosts')}; "
        f"SPF: {d.get('has_spf')}; DMARC: {d.get('has_dmarc')}",
    ]
    if signals.get("page_text_excerpt"):
        lines.append(f"\nVisible page text (truncated):\n{signals['page_text_excerpt']}")
    return "\n".join(lines)


SYSTEM_PROMPT = (
    "You are a senior SOC analyst triaging suspected brand-impersonation domains. "
    "You are given hard signals collected from a suspect domain. Judge how WEAPONIZED "
    "the domain is right now, not merely whether it looks similar. A working "
    "credential-harvest/login clone is P1; stood-up impersonation infrastructure that "
    "is mail-capable or a clone but not yet confirmed harvesting is P2; a "
    "registered/parked/placeholder lookalike is P3; clearly benign, defensive, or "
    "unrelated is P4. Do not over-escalate parked or for-sale domains."
)


def score(domain: str, brand: Optional[str] = None,
          llm: Optional[Callable[[str], Dict[str, Any]]] = None,
          **kwargs: Any) -> Dict[str, Any]:
    """Gather signals and produce a verdict.

    Args:
        domain: the suspect domain.
        brand: the legitimate brand it may impersonate (sharpens the verdict).
        llm: optional callable taking the facts prompt and returning a verdict
            dict. If omitted, the deterministic :func:`heuristic_tier` is used.
        **kwargs: forwarded to :func:`gather_signals` (``timeout``, ``verify_tls``).

    Returns:
        ``{domain, signals, tier, verdict, source}`` where ``source`` is
        ``"heuristic"`` or ``"llm"``.
    """
    signals = gather_signals(domain, brand=brand, **kwargs)
    if llm is not None:
        try:
            verdict = llm(facts_prompt(signals))
            return {"domain": domain, "signals": signals,
                    "tier": verdict.get("tier") or verdict.get("risk_tier"),
                    "verdict": verdict, "source": "llm"}
        except Exception as e:
            verdict = heuristic_tier(signals)
            verdict["llm_error"] = f"{type(e).__name__}: {e}"
            return {"domain": domain, "signals": signals, "tier": verdict["tier"],
                    "verdict": verdict, "source": "heuristic"}
    verdict = heuristic_tier(signals)
    return {"domain": domain, "signals": signals, "tier": verdict["tier"],
            "verdict": verdict, "source": "heuristic"}


def openai_verdict(base_url: str, api_key: str, model: str,
                   timeout: int = 60) -> Callable[[str], Dict[str, Any]]:
    """Build an ``llm=`` callable backed by any OpenAI-compatible chat endpoint.

    Example::

        llm = openai_verdict("https://api.openai.com/v1", key, "gpt-4o-mini")
        result = score("acme-login.com", brand="acme", llm=llm)
    """
    requests = _requests()
    import json as _json

    def _call(prompt: str) -> Dict[str, Any]:
        resp = requests.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model, "temperature": 0,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT + " Respond as JSON with keys: "
                     "tier (P1-P4), is_active_phishing (bool), rationale (string)."},
                    {"role": "user", "content": prompt},
                ],
            }, timeout=timeout,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return _json.loads(content)

    return _call

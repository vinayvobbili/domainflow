"""Model round-tripping and the offline scoring heuristic (no network)."""

from domainflow.models import Finding, Campaign, Pivot
from domainflow.score import heuristic_tier, transition


def test_finding_from_dict_tolerates_aliases():
    f = Finding.from_dict({
        "domain": "ACME-Login.com ",
        "registrant": "Foo LLC",          # alias for registrant_org
        "dns_a": "5.5.5.5",               # scalar alias for ip_addresses
        "name_servers": ["ns1.x.com"],
        "issuer": "Let's Encrypt",
        "weaponization_active": 1,
        "xsoar_id": "INC-1",
    })
    assert f.domain == "acme-login.com"
    assert f.registrant_org == "Foo LLC"
    assert f.ip_addresses == ["5.5.5.5"]
    assert f.cert_issuer == "Let's Encrypt"
    assert f.active is True
    assert f.contained is True


def test_campaign_size_and_dict():
    c = Campaign(id=1, domains=["a.com", "b.com"], pivots=[Pivot("ip", "1.1.1.1", 2)])
    d = c.to_dict()
    assert d["size"] == 2
    assert d["pivots"][0]["value"] == "1.1.1.1"


def test_heuristic_p1_live_login_clone():
    sig = {"page": {"reachable": True, "has_password_input": True, "has_form": True},
           "dns": {}, "brand_in_page": True}
    v = heuristic_tier(sig)
    assert v["tier"] == "P1"
    assert v["is_active_phishing"] is True


def test_heuristic_p4_unreachable():
    sig = {"page": {"reachable": False}, "dns": {"has_mx": False}, "brand_in_page": None}
    assert heuristic_tier(sig)["tier"] == "P4"


def test_heuristic_p2_mail_capable_reachable():
    sig = {"page": {"reachable": True, "has_form": False, "has_password_input": False},
           "dns": {"has_mx": True}, "brand_in_page": False}
    assert heuristic_tier(sig)["tier"] == "P2"


def _dormant():
    return {"tier": "P4", "signals": {"page": {"reachable": False}, "dns": {"has_mx": False}}}


def _live_p2(domain="acme-login.com"):
    return {"domain": domain, "tier": "P2",
            "signals": {"page": {"reachable": True}, "dns": {"has_mx": True}}}


def test_transition_became_active_escalates():
    t = transition(_dormant(), _live_p2(), dormant_days=92)
    assert t["became_active"] is True
    assert t["current_tier"] == "P2"
    assert t["recommended_tier"] == "P1"   # boosted one notch on the dormant→live flip
    assert t["priority_boost"] is True
    assert "92 days" in t["rationale"]
    assert t["domain"] == "acme-login.com"


def test_transition_p3_became_active_boosts_to_p2():
    cur = {"domain": "x.com", "tier": "P3",
           "signals": {"page": {"reachable": True}, "dns": {"has_mx": False}}}
    t = transition(_dormant(), cur)
    assert t["recommended_tier"] == "P2"
    assert t["priority_boost"] is True


def test_transition_none_previous_treated_as_dormant():
    t = transition(None, _live_p2())
    assert t["became_active"] is True


def test_transition_steady_live_no_boost():
    t = transition(_live_p2(), _live_p2())
    assert t["became_active"] is False
    assert t["priority_boost"] is False
    assert t["recommended_tier"] == "P2"


def test_transition_went_dormant():
    t = transition(_live_p2(), _dormant())
    assert t["went_dormant"] is True
    assert t["priority_boost"] is False


def test_transition_accepts_raw_signals_dict():
    prev = {"page": {"reachable": False}, "dns": {"has_mx": False}}
    cur = {"domain": "y.com", "page": {"reachable": True}, "dns": {}}
    t = transition(prev, cur)
    assert t["became_active"] is True
    assert t["domain"] == "y.com"

"""Model round-tripping and the offline scoring heuristic (no network)."""

from domainflow.models import Finding, Campaign, Pivot
from domainflow.score import heuristic_tier


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

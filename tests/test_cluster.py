"""Campaign clustering — the flagship. Verifies real campaigns merge and noise
infrastructure (bulk registrar / Let's Encrypt / Cloudflare) does NOT."""

from domainflow import cluster_campaigns, Finding


def test_shared_ip_and_registrant_merge():
    findings = [
        {"domain": "acme-login.com", "brand": "Acme", "ip_addresses": ["5.5.5.5"],
         "registrant_org": "Foo Holdings", "nameservers": ["ns1.cloudflare.com"],
         "registrar": "GoDaddy", "active": True},
        {"domain": "acme-secure.com", "brand": "Acme", "ip_addresses": ["5.5.5.5"],
         "registrant_org": "Foo Holdings", "registrar": "GoDaddy"},
        {"domain": "acme-verify.net", "brand": "Acme", "ip_addresses": ["9.9.9.9"],
         "registrant_org": "foo holdings", "registrar": "Namecheap"},
    ]
    camps = cluster_campaigns(findings)
    assert len(camps) == 1
    c = camps[0]
    assert c.size == 3
    assert c.any_active is True
    # registrant (case-normalised) binds all three; IP binds two.
    pivot_types = {p.type for p in c.pivots}
    assert "registrant" in pivot_types
    assert "ip" in pivot_types


def test_noise_pivots_do_not_merge():
    # Same bulk registrar + Cloudflare NS + Let's Encrypt, but distinct IP and
    # a privacy-protected registrant -> must NOT cluster with anything.
    findings = [
        {"domain": "acme-a.com", "ip_addresses": ["5.5.5.5"], "registrant_org": "Foo Holdings"},
        {"domain": "acme-b.com", "ip_addresses": ["5.5.5.5"], "registrant_org": "Foo Holdings"},
        {"domain": "random-bank.com", "ip_addresses": ["1.2.3.4"],
         "nameservers": ["ns1.cloudflare.com"], "cert_issuer": "Let's Encrypt",
         "registrar": "GoDaddy", "registrant_org": "REDACTED FOR PRIVACY"},
    ]
    camps = cluster_campaigns(findings)
    assert len(camps) == 1
    assert set(camps[0].domains) == {"acme-a.com", "acme-b.com"}


def test_nameserver_campaign():
    findings = [
        {"domain": "x-a.com", "brand": "X", "nameservers": ["ns1.evilhost.ru"]},
        {"domain": "x-b.com", "brand": "X", "nameservers": ["ns1.evilhost.ru"]},
    ]
    camps = cluster_campaigns(findings)
    assert len(camps) == 1
    assert camps[0].pivots[0].type == "nameserver"


def test_oversharing_pivot_suppressed():
    # An IP shared by every domain is infrastructure, not a campaign.
    findings = [{"domain": f"d{i}.com", "ip_addresses": ["1.1.1.1"]} for i in range(10)]
    camps = cluster_campaigns(findings)
    assert camps == []


def test_singletons_excluded():
    findings = [{"domain": "lonely.com", "ip_addresses": ["7.7.7.7"]}]
    assert cluster_campaigns(findings) == []


def test_accepts_finding_objects():
    findings = [
        Finding(domain="a.com", ip_addresses=["2.2.2.2"]),
        Finding(domain="b.com", ip_addresses=["2.2.2.2"]),
    ]
    camps = cluster_campaigns(findings)
    assert len(camps) == 1
    assert camps[0].size == 2


def test_active_first_ordering():
    findings = [
        {"domain": "calm-a.com", "ip_addresses": ["3.3.3.3"]},
        {"domain": "calm-b.com", "ip_addresses": ["3.3.3.3"]},
        {"domain": "hot-a.com", "ip_addresses": ["4.4.4.4"], "active": True},
        {"domain": "hot-b.com", "ip_addresses": ["4.4.4.4"], "active": True},
    ]
    camps = cluster_campaigns(findings)
    assert len(camps) == 2
    assert camps[0].any_active is True  # active campaign sorts first
    assert camps[0].id == 1

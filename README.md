# domainflow

**The lookalike-domain lifecycle, as a toolkit you can `pip install`.** Generate
the typo-squat space for a brand, find which candidates are real (Certificate
Transparency + WHOIS), score how weaponized they are, and **cluster** the
findings that share an actor's infrastructure into campaigns — so a coordinated
wave of impersonations reads as *one* thing, not fifty scattered alerts.

Offline-safe core, model-agnostic, no vendor lock-in.

```python
from domainflow import generate_lookalikes, cluster_campaigns

# 1. Generate the impersonation space for a brand
for la in generate_lookalikes("acme.com"):
    print(la.fuzzer, la.domain)        # homoglyph ecme.com, tld-swap acme.xyz, …

# 2. (after you've enriched some findings) cluster by shared infrastructure
findings = [
    {"domain": "acme-login.com", "ip_addresses": ["5.5.5.5"], "registrant_org": "Foo Holdings"},
    {"domain": "acme-secure.com", "ip_addresses": ["5.5.5.5"], "registrant_org": "Foo Holdings"},
    {"domain": "acme-verify.net", "ip_addresses": ["9.9.9.9"], "registrant_org": "foo holdings"},
]
for c in cluster_campaigns(findings):
    print(c.size, [p.value for p in c.pivots], c.domains)
    # 3 ['foo holdings', '5.5.5.5'] ['acme-login.com', 'acme-secure.com', 'acme-verify.net']
```

## Why

Plenty of tools *generate* typo-squats (dnstwist) or *stream* Certificate
Transparency. What's missing is the part that turns a pile of lookalike alerts
into something a human can act on: **which of these belong to the same actor?**

domainflow's flagship is the clustering. The hard part isn't grouping by shared
IP/registrant/nameserver — it's *not over-grouping*. Phishing kits overwhelmingly
reuse a few bulk registrars, Let's Encrypt, and Cloudflare, so a naive join
collapses every unrelated domain into one giant blob. domainflow only joins on
*discriminating* pivots and suppresses values that are too common to mean
anything — so a cluster reflects a genuinely linked set of registrations.

## Install

```bash
pip install domainflow                 # core: discover + cluster (stdlib only)
pip install domainflow[ct]             # + Certificate Transparency (crt.sh)
pip install domainflow[whois]          # + WHOIS snapshot/diff
pip install domainflow[score]          # + weaponization signals (page + DNS)
pip install domainflow[all]            # everything
```

## The four layers

### `discover` — generate the impersonation space

```python
from domainflow import generate_lookalikes, FUZZERS

generate_lookalikes("acme.com")                          # high-signal default set
generate_lookalikes("acme.com", fuzzers=["homoglyph"])   # one technique
generate_lookalikes("acme.com", fuzzers=list(FUZZERS) + ["dictionary-combo"])  # everything
generate_lookalikes("acme.com", keywords=["claims", "benefits"])  # custom brand+keyword
```

Fuzzers: `homoglyph`, `omission`, `repetition`, `transposition`, `replacement`,
`insertion`, `vowel-swap`, `hyphenation`, `addition`, `bitsquatting`, `tld-swap`,
`dictionary-combo`, `industry-tld`, `split-brand`.

### `monitor` — find which candidates are real

```python
from domainflow.monitor import ct, whois

ct.discovered_domains("acme")           # domains from new certs mentioning "acme"
snap = whois.snapshot("acme-login.com") # normalised registration facts
whois.diff(previous_snap, snap)         # [{field: 'name_servers', severity: 'high', …}]
```

### `score` — is it weaponized?

```python
from domainflow import score

r = score.score("acme-login.com", brand="acme")
print(r["tier"])                        # P1 (live login clone) … P4 (parked/benign)

# bring your own LLM for a sharper verdict — any OpenAI-compatible endpoint
llm = score.openai_verdict("https://api.openai.com/v1", api_key, "gpt-4o-mini")
score.score("acme-login.com", brand="acme", llm=llm)
```

Offline, the tier comes from a deterministic heuristic over page + MX/SPF/DMARC
signals. No model required.

`score` is *point-in-time*. To catch the strongest tell — a lookalike that sat
dormant for weeks and then **suddenly went live** (deliberate, aged
infrastructure) — diff this scan against the last one:

```python
prev = load_last_score("acme-login.com")        # whatever you stored last scan
now = score.score("acme-login.com", brand="acme")

t = score.transition(prev, now, dormant_days=92)
if t["became_active"]:
    print(t["recommended_tier"], t["rationale"])  # e.g. P2 → escalated to P1
```

On a dormant→live flip, `transition` recommends a one-notch escalation above the
point-in-time tier — a freshly-activated aged domain outranks a brand-new live
one of the same tier. It also reports `went_dormant`, `escalated`/`deescalated`,
and is pure (no network), so it works without the `score` extra.

> Retention tip: don't expire dormant lookalikes. The quiet domain at day 31 is
> exactly the one this catches when it activates — archive, don't delete, and
> keep its `first_seen` so you can pass `dormant_days`.

### `cluster` — group findings into campaigns

```python
from domainflow import cluster_campaigns

campaigns = cluster_campaigns(findings)   # list[Finding] or list[dict]
for c in campaigns:                       # sorted active-first, then largest-first
    print(c.id, c.size, c.brands, [(p.type, p.value) for p in c.pivots])
```

A `Finding` needs only a `domain`; populate `ip_addresses`, `registrant_org`,
`nameservers` (and optionally `active`/`contained`) for richer clustering. Loose
dicts are coerced, tolerating common key aliases (`dns_a`, `name_servers`,
`issuer`, `registrant`, …).

## CLI

```bash
domainflow discover acme.com
domainflow ct acme --domains
domainflow whois acme-login.com
domainflow score acme-login.com --brand acme
domainflow cluster findings.json
```

## Design notes

- **Core is stdlib-only.** `discover` and `cluster` have zero dependencies;
  network layers are opt-in extras.
- **No storage imposed.** Everything is plain dataclasses with
  `to_dict`/`from_dict`. Bring your own database.
- **Model-agnostic.** Scoring works offline; the LLM path is a callable you
  supply.

## License

MIT

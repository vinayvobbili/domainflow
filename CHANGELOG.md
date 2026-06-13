# Changelog

All notable changes to domainflow are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0]

Initial release. The lookalike-domain lifecycle as four composable layers.

### Added
- **discover** — stdlib lookalike/typo-squat generation: homoglyph, omission,
  repetition, transposition, replacement, insertion, vowel-swap, hyphenation,
  addition, bitsquatting, plus brand-impersonation combos (suspicious TLD swap,
  brand+keyword, industry gTLD, split-brand).
- **monitor.ct** — Certificate Transparency search via crt.sh (`ct` extra).
- **monitor.whois** — WHOIS snapshot + change detection (`whois` extra).
- **score** — weaponization signals (page + MX/SPF/DMARC) with an offline
  heuristic tier and a bring-your-own-LLM verdict, including an OpenAI-compatible
  caller (`score` / `llm` extras).
- **cluster** — campaign clustering: group findings sharing an actor's
  infrastructure (IP, registrant, nameserver) via union-find, with
  noise-suppression so bulk registrars / Let's Encrypt / CDNs don't over-merge.
- `domainflow` CLI: `discover`, `ct`, `whois`, `score`, `cluster`.

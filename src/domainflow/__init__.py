"""domainflow — the lookalike-domain lifecycle as a pip-installable toolkit.

Four layers, each usable on its own:

- **discover** — generate the lookalike/typo-squat space for a brand domain
  (homoglyphs, omissions, transpositions, TLD swaps, brand+keyword combos).
- **monitor** — find which of those are real: Certificate Transparency (crt.sh)
  and WHOIS snapshot/diff.
- **score** — turn "a lookalike exists" into "is it weaponized?" via page +
  mail (MX/SPF/DMARC) signals, with an optional bring-your-own-LLM verdict.
- **cluster** — group findings that share an actor's footprint (IP, registrant,
  nameserver) into campaigns, so a coordinated wave reads as one thing.

The core (discover + cluster) is stdlib-only. Network layers are optional
extras: ``pip install domainflow[ct,whois,score]``.
"""

from .models import Campaign, Finding, Lookalike
from .discover import generate_lookalikes, FUZZERS
from .cluster import cluster_campaigns

__version__ = "0.1.0"

__all__ = [
    "Campaign",
    "Finding",
    "Lookalike",
    "generate_lookalikes",
    "FUZZERS",
    "cluster_campaigns",
    "__version__",
]

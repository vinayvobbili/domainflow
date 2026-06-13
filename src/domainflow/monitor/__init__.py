"""Find which candidate domains are real, via public observation points.

- :mod:`domainflow.monitor.ct` — Certificate Transparency (crt.sh). A new TLS
  cert for ``acme-login.com`` is strong evidence someone stood it up.
- :mod:`domainflow.monitor.whois` — WHOIS snapshot + change detection (new
  registration, registrant/nameserver change = infrastructure move).

Both are optional extras::

    pip install domainflow[ct]      # crt.sh
    pip install domainflow[whois]   # WHOIS
"""

from . import ct, whois

__all__ = ["ct", "whois"]

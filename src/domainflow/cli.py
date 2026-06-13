"""domainflow command-line interface.

    domainflow discover acme.com
    domainflow ct acme
    domainflow whois acme-login.com
    domainflow score acme-login.com --brand acme
    domainflow cluster findings.json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List

from . import __version__
from .discover import generate_lookalikes, FUZZERS, DEFAULT_FUZZERS
from .cluster import cluster_campaigns


def _print_json(obj: Any) -> None:
    json.dump(obj, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


def _cmd_discover(args: argparse.Namespace) -> int:
    fuzzers = args.fuzzers.split(",") if args.fuzzers else None
    las = generate_lookalikes(args.domain, fuzzers=fuzzers)
    if args.json:
        _print_json([la.to_dict() for la in las])
    else:
        for la in las:
            print(f"{la.fuzzer:16} {la.domain}")
        print(f"\n{len(las)} candidates", file=sys.stderr)
    return 0


def _cmd_ct(args: argparse.Namespace) -> int:
    from .monitor import ct
    if args.domains:
        _print_json(ct.discovered_domains(args.query, exclude_expired=args.active))
    else:
        _print_json(ct.search_certs(args.query, exclude_expired=args.active))
    return 0


def _cmd_whois(args: argparse.Namespace) -> int:
    from .monitor import whois
    _print_json(whois.snapshot(args.domain))
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    from . import score as score_mod
    result = score_mod.score(args.domain, brand=args.brand, verify_tls=not args.insecure)
    _print_json(result)
    return 0


def _cmd_cluster(args: argparse.Namespace) -> int:
    with open(args.findings) as f:
        findings: List[dict] = json.load(f)
    campaigns = cluster_campaigns(findings)
    _print_json([c.to_dict() for c in campaigns])
    if not args.json_only:
        print(f"\n{len(campaigns)} campaign(s) from {len(findings)} findings", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="domainflow", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"domainflow {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("discover", help="generate lookalike candidates for a domain")
    d.add_argument("domain")
    d.add_argument("--fuzzers", help=f"comma-separated subset of: {','.join(FUZZERS)},dictionary-combo "
                                     f"(default: {','.join(DEFAULT_FUZZERS)})")
    d.add_argument("--json", action="store_true", help="emit JSON")
    d.set_defaults(func=_cmd_discover)

    c = sub.add_parser("ct", help="Certificate Transparency search (crt.sh)")
    c.add_argument("query")
    c.add_argument("--domains", action="store_true", help="emit just the domain list")
    c.add_argument("--active", action="store_true", help="exclude expired certs")
    c.set_defaults(func=_cmd_ct)

    w = sub.add_parser("whois", help="WHOIS snapshot for a domain")
    w.add_argument("domain")
    w.set_defaults(func=_cmd_whois)

    s = sub.add_parser("score", help="weaponization signals + tier for a domain")
    s.add_argument("domain")
    s.add_argument("--brand", help="the legitimate brand it may impersonate")
    s.add_argument("--insecure", action="store_true", help="skip TLS verification on the page fetch")
    s.set_defaults(func=_cmd_score)

    cl = sub.add_parser("cluster", help="cluster a JSON list of findings into campaigns")
    cl.add_argument("findings", help="path to a JSON array of finding objects")
    cl.add_argument("--json-only", action="store_true", help="suppress the summary line")
    cl.set_defaults(func=_cmd_cluster)

    return p


def main(argv: Any = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

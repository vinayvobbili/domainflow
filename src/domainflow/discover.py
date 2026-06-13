"""Generate the lookalike / typo-squat space for a brand domain.

Pure stdlib — no dnstwist, no network. Produces candidate domains an attacker
might register to impersonate ``brand.tld``, labelled by the technique
(*fuzzer*) that produced each one. Feed the output to :mod:`domainflow.monitor`
to find which candidates are actually registered.

Two families of generators:

- **Classic typo-squats** — homoglyph, omission, repetition, transposition,
  replacement, insertion, vowel-swap, hyphenation, addition, bitsquatting.
- **Brand-impersonation combos** — suspicious TLD swaps, brand+keyword
  combinations, industry gTLDs, and split-brand hyphenations. These catch
  registrations that fuzzing alone misses (e.g. ``acme-login.com``).

Example::

    from domainflow import generate_lookalikes
    for la in generate_lookalikes("acme.com"):
        print(la.fuzzer, la.domain)
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Set

from .models import Lookalike

# Visually-confusable single-character substitutions (homoglyphs).
_HOMOGLYPHS: Dict[str, List[str]] = {
    "a": ["e", "o", "4", "@"], "b": ["d", "lb", "ib", "6", "8"],
    "c": ["e", "o"], "d": ["b", "cl"], "e": ["a", "c", "3"],
    "g": ["q", "9", "6"], "i": ["1", "l", "j", "!"], "j": ["i"],
    "l": ["1", "i", "I"], "m": ["n", "rn", "nn"], "n": ["m", "r"],
    "o": ["0", "c", "q"], "q": ["g", "o"], "s": ["5", "$", "z"],
    "t": ["7", "+"], "u": ["v"], "v": ["u", "w"], "w": ["vv"],
    "z": ["s", "2"], "0": ["o"], "1": ["l", "i"],
}

# Keyboard-adjacent characters (QWERTY) for replacement/insertion fuzzers.
_KEYBOARD: Dict[str, str] = {
    "q": "wa", "w": "qase", "e": "wsdr", "r": "edft", "t": "rfgy",
    "y": "tghu", "u": "yhji", "i": "ujko", "o": "iklp", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc",
    "g": "ftyhbv", "h": "gyujnb", "j": "huikmn", "k": "jiolm",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
}

_VOWELS = "aeiou"

# Suspicious / commonly-abused TLDs for the tld-swap fuzzer.
SUSPICIOUS_TLDS: List[str] = [
    "tk", "buzz", "xyz", "top", "ga", "ml", "info", "cf", "gq", "icu",
    "wang", "live", "net", "online", "host", "org", "us", "co",
    "dev", "io", "app", "ai", "tech", "site", "click", "link", "shop",
]

# Generic phishing keywords for brand+keyword combinations. Override via the
# ``keywords`` argument for an industry-specific list.
DEFAULT_KEYWORDS: List[str] = [
    "login", "signin", "secure", "verify", "auth", "account", "portal",
    "access", "support", "help", "service", "update", "pay", "payment",
    "billing", "home", "online", "web", "app", "my", "go", "get", "mail",
    "email", "vpn", "cloud", "api", "mobile", "admin", "corp", "global",
]

# Brand-relevant gTLDs that read as legitimate to a victim.
INDUSTRY_TLDS: List[str] = [
    "app", "cloud", "digital", "tech", "email", "company", "corp", "inc",
    "group", "global", "services", "solutions", "support", "help", "center",
    "secure", "security", "online", "site", "shop", "store",
]

_KEYWORD_TLDS = ["com", "net", "org", "co", "io", "app"]


def _split(domain: str) -> Optional[tuple]:
    """Return (label, tld) for the registrable name, or None if unsplittable.

    Naive last-dot split — fine for ``brand.com``; multi-label public suffixes
    (``brand.co.uk``) treat ``co.uk`` as label+tld. Callers needing exact public
    suffix handling should pre-normalise to the registrable domain.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if "." not in domain:
        return None
    label, tld = domain.rsplit(".", 1)
    if not label or not tld:
        return None
    return label, tld


# --- classic typo-squat fuzzers -------------------------------------------
# Each takes (label, tld) and yields candidate full domains.

def _f_homoglyph(label: str, tld: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for repl in _HOMOGLYPHS.get(ch, []):
            out.add(f"{label[:i]}{repl}{label[i + 1:]}.{tld}")
    return out


def _f_omission(label: str, tld: str) -> Set[str]:
    return {f"{label[:i]}{label[i + 1:]}.{tld}" for i in range(len(label)) if len(label) > 2}


def _f_repetition(label: str, tld: str) -> Set[str]:
    return {f"{label[:i + 1]}{label[i]}{label[i + 1:]}.{tld}" for i in range(len(label))}


def _f_transposition(label: str, tld: str) -> Set[str]:
    out = set()
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            out.add(f"{label[:i]}{label[i + 1]}{label[i]}{label[i + 2:]}.{tld}")
    return out


def _f_replacement(label: str, tld: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for repl in _KEYBOARD.get(ch, ""):
            out.add(f"{label[:i]}{repl}{label[i + 1:]}.{tld}")
    return out


def _f_insertion(label: str, tld: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for ins in _KEYBOARD.get(ch, ""):
            out.add(f"{label[:i]}{ins}{label[i:]}.{tld}")
    return out


def _f_vowel_swap(label: str, tld: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        if ch in _VOWELS:
            for v in _VOWELS:
                if v != ch:
                    out.add(f"{label[:i]}{v}{label[i + 1:]}.{tld}")
    return out


def _f_hyphenation(label: str, tld: str) -> Set[str]:
    return {f"{label[:i]}-{label[i:]}.{tld}" for i in range(1, len(label))}


def _f_addition(label: str, tld: str) -> Set[str]:
    return {f"{label}{c}.{tld}" for c in "abcdefghijklmnopqrstuvwxyz0123456789"}


def _f_bitsquatting(label: str, tld: str) -> Set[str]:
    out = set()
    for i, ch in enumerate(label):
        for bit in (1, 2, 4, 8, 16, 32, 64, 128):
            c = chr(ord(ch) ^ bit)
            if c.isalnum() or c == "-":
                out.add(f"{label[:i]}{c}{label[i + 1:]}.{tld}")
    return out


# --- brand-impersonation combo fuzzers ------------------------------------

def _f_tld_swap(label: str, tld: str) -> Set[str]:
    return {f"{label}.{t}" for t in SUSPICIOUS_TLDS if t != tld}


def _f_industry_tld(label: str, tld: str) -> Set[str]:
    return {f"{label}.{t}" for t in INDUSTRY_TLDS if t != tld}


def _f_split_brand(label: str, tld: str) -> Set[str]:
    if len(label) < 3:
        return set()
    return {f"{label[:i]}-{label[i:]}.com" for i in range(1, len(label))}


# dictionary-combo is keyword-parameterised, so it's handled specially below.

FUZZERS: Dict[str, Callable[[str, str], Set[str]]] = {
    "homoglyph": _f_homoglyph,
    "omission": _f_omission,
    "repetition": _f_repetition,
    "transposition": _f_transposition,
    "replacement": _f_replacement,
    "insertion": _f_insertion,
    "vowel-swap": _f_vowel_swap,
    "hyphenation": _f_hyphenation,
    "addition": _f_addition,
    "bitsquatting": _f_bitsquatting,
    "tld-swap": _f_tld_swap,
    "industry-tld": _f_industry_tld,
    "split-brand": _f_split_brand,
}

# Default selection: the high-signal generators. Excludes the noisier
# addition/bitsquatting/insertion sets unless explicitly requested.
DEFAULT_FUZZERS: List[str] = [
    "homoglyph", "omission", "repetition", "transposition", "replacement",
    "vowel-swap", "hyphenation", "tld-swap", "industry-tld", "split-brand",
    "dictionary-combo",
]


def _dictionary_combos(label: str, tld: str, keywords: List[str]) -> Set[str]:
    out: Set[str] = set()
    for word in keywords:
        for t in _KEYWORD_TLDS:
            if t == tld:
                out.update({
                    f"{label}{word}.{t}", f"{word}{label}.{t}",
                    f"{label}-{word}.{t}", f"{word}-{label}.{t}",
                })
            else:
                out.update({f"{label}-{word}.{t}", f"{word}-{label}.{t}"})
    return out


def generate_lookalikes(
    domain: str,
    fuzzers: Optional[List[str]] = None,
    keywords: Optional[List[str]] = None,
) -> List[Lookalike]:
    """Generate the lookalike space for ``domain``.

    Args:
        domain: the legitimate domain to protect, e.g. ``"acme.com"``.
        fuzzers: which generators to run (see :data:`FUZZERS`). Defaults to
            :data:`DEFAULT_FUZZERS`. Pass ``list(FUZZERS) + ["dictionary-combo"]``
            for everything.
        keywords: brand+keyword list for the ``dictionary-combo`` fuzzer.
            Defaults to :data:`DEFAULT_KEYWORDS`.

    Returns:
        A de-duplicated list of :class:`~domainflow.models.Lookalike`, excluding
        the original domain. Each carries the fuzzer that produced it (the first
        one, if several would).
    """
    parts = _split(domain)
    if not parts:
        return []
    label, tld = parts
    original = f"{label}.{tld}"
    selected = fuzzers if fuzzers is not None else DEFAULT_FUZZERS
    kw = keywords if keywords is not None else DEFAULT_KEYWORDS

    seen: Set[str] = set()
    results: List[Lookalike] = []
    for name in selected:
        if name == "dictionary-combo":
            candidates = _dictionary_combos(label, tld, kw)
        else:
            fn = FUZZERS.get(name)
            if not fn:
                continue
            candidates = fn(label, tld)
        for cand in sorted(candidates):
            if cand == original or cand in seen:
                continue
            seen.add(cand)
            results.append(Lookalike(domain=cand, fuzzer=name, target=original))
    return results

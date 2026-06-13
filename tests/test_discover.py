"""Lookalike generation — coverage of the fuzzer families and edge cases."""

from domainflow import generate_lookalikes, FUZZERS
from domainflow.discover import DEFAULT_FUZZERS


def test_basic_generation_excludes_original():
    las = generate_lookalikes("acme.com")
    domains = {la.domain for la in las}
    assert "acme.com" not in domains
    assert len(domains) == len(las)  # de-duplicated


def test_homoglyph_produces_known_variant():
    las = generate_lookalikes("acme.com", fuzzers=["homoglyph"])
    domains = {la.domain for la in las}
    # 'a' -> 'e' is in the homoglyph table.
    assert "ecme.com" in domains


def test_tld_swap():
    las = generate_lookalikes("acme.com", fuzzers=["tld-swap"])
    domains = {la.domain for la in las}
    assert "acme.xyz" in domains
    assert "acme.com" not in domains  # same-tld skipped


def test_dictionary_combo_uses_keywords():
    las = generate_lookalikes("acme.com", fuzzers=["dictionary-combo"],
                              keywords=["login"])
    domains = {la.domain for la in las}
    assert "acme-login.com" in domains
    assert "login-acme.com" in domains


def test_split_brand():
    las = generate_lookalikes("acme.com", fuzzers=["split-brand"])
    domains = {la.domain for la in las}
    assert "ac-me.com" in domains


def test_unsplittable_domain_returns_empty():
    assert generate_lookalikes("localhost") == []
    assert generate_lookalikes("") == []


def test_fuzzer_label_recorded():
    las = generate_lookalikes("acme.com", fuzzers=["tld-swap"])
    assert all(la.fuzzer == "tld-swap" for la in las)
    assert all(la.target == "acme.com" for la in las)


def test_all_fuzzers_run_without_error():
    las = generate_lookalikes("acme.com", fuzzers=list(FUZZERS) + ["dictionary-combo"])
    assert len(las) > 0


def test_default_fuzzers_is_subset_of_registry():
    for name in DEFAULT_FUZZERS:
        assert name in FUZZERS or name == "dictionary-combo"

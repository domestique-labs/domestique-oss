from domestique.taxonomy import CANONICAL, MAX_PREFIX_LEN, prefix_for
from domestique.taxonomy_store import TaxonomyStore


def test_register_coins_and_persists(tmp_path):
    path = tmp_path / "taxonomy.json"
    store = TaxonomyStore(path=path)
    prefix = store.register("Employee ID")
    assert prefix == "EMPLOYEE_ID"
    # reload from disk sees it
    reloaded = TaxonomyStore(path=path)
    assert reloaded.prefix_of("employee_id") == "EMPLOYEE_ID"


def test_register_avoids_collision_with_canonical(tmp_path):
    store = TaxonomyStore(path=tmp_path / "t.json")
    # a coined term whose derived prefix collides with a canonical one gets a suffix
    prefix = store.register("person")  # canonical → returns canonical, not stored
    assert prefix == CANONICAL["person"]
    assert store.prefix_of("person") is None  # canonical never stored


def test_register_collision_between_coined_terms_stays_within_max_prefix_len(tmp_path):
    store = TaxonomyStore(path=tmp_path / "t.json")
    # Two distinct coined terms that agree on their first MAX_PREFIX_LEN
    # uppercased characters (and differ only after) derive the same base
    # prefix, forcing the second registration through the collision path.
    prefix1 = store.register("some very long category alpha")
    prefix2 = store.register("some very long category beta")
    assert prefix1 != prefix2  # second one must have gotten a disambiguating suffix
    assert len(prefix1) <= MAX_PREFIX_LEN
    assert len(prefix2) <= MAX_PREFIX_LEN


def test_register_is_idempotent(tmp_path):
    store = TaxonomyStore(path=tmp_path / "t.json")
    a = store.register("badge number")
    b = store.register("badge_number")
    assert a == b


def test_failsafe_without_writable_path():
    store = TaxonomyStore(path=None)  # in-memory only
    assert store.register("cluster secret") == "CLUSTER_SECRET"
    assert store.prefix_of("cluster_secret") == "CLUSTER_SECRET"


def test_prefix_for_consults_default_store(tmp_path, monkeypatch):
    import domestique.taxonomy_store as ts

    store = TaxonomyStore(path=tmp_path / "t.json")
    store.register("employee id")
    monkeypatch.setattr(ts, "_DEFAULT", store)
    assert prefix_for("employee_id") == "EMPLOYEE_ID"


def test_over_long_coined_term_is_not_persisted(tmp_path):
    # The LLM `c` field is untrusted; an over-long value (a hallucination that
    # may echo prompt text) must yield a usable bounded prefix but never grow
    # the on-disk file.
    path = tmp_path / "t.json"
    store = TaxonomyStore(path=path)
    prefix = store.register("leak " + "x" * 500)
    assert len(prefix) <= MAX_PREFIX_LEN  # still bounded + usable as a token prefix
    assert store.terms() == {}  # not kept in memory
    assert not path.exists()  # nothing written to disk
    # a normal short coined term is still persisted as before
    short = store.register("employee badge")
    assert store.prefix_of("employee_badge") == short
    assert path.exists()


def test_total_coined_terms_capped(tmp_path, monkeypatch):
    import domestique.taxonomy_store as ts

    monkeypatch.setattr(ts, "_MAX_COINED_TERMS", 3)
    store = TaxonomyStore(path=tmp_path / "t.json")
    for i in range(3):
        store.register(f"coined term {i}")
    assert len(store.terms()) == 3
    overflow = store.register("one too many")
    assert len(overflow) <= MAX_PREFIX_LEN  # still returns a bounded prefix
    assert len(store.terms()) == 3  # but is not stored
    assert "one_too_many" not in store.terms()

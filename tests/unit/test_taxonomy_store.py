from domestique.taxonomy import CANONICAL, prefix_for
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

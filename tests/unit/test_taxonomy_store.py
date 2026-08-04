import json
import stat
import sys

import pytest
import structlog.testing

from domestique.taxonomy import CANONICAL, GENERIC_PREFIX, MAX_PREFIX_LEN, prefix_for
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
    # Label-shaped names: "coined term 0" snake-cases to coined_term_0, whose
    # trailing digit-only word the shape guard rejects. This test is about the
    # count cap, not the shape guard.
    for word in ("alpha", "beta", "gamma"):
        store.register(f"coined term {word}")
    assert len(store.terms()) == 3
    overflow = store.register("one too many")
    assert len(overflow) <= MAX_PREFIX_LEN  # still returns a bounded prefix
    assert len(store.terms()) == 3  # but is not stored
    assert "one_too_many" not in store.terms()


class TestValueLikeCategoryRejected:
    """The LLM ``c`` field is untrusted. A model that echoes a secret into it
    would otherwise mint a token containing that secret (sent upstream) and
    persist it as a key in ~/.domestique/taxonomy.json.
    """

    SECRET = "Tr0ub4dor3xKlm9zQvBn7Yt2"
    TEXT = f"the deploy password is {SECRET} rotate it monthly"

    def test_value_like_category_is_rejected_and_never_persisted(self, tmp_path):
        path = tmp_path / "t.json"
        store = TaxonomyStore(path=path)
        prefix = store.register(self.SECRET, scanned_text=self.TEXT)
        assert prefix == GENERIC_PREFIX
        assert store.terms() == {}
        assert not path.exists(), "the secret was written to disk"

    def test_rejection_log_carries_neither_the_term_nor_the_text(self, tmp_path):
        store = TaxonomyStore(path=tmp_path / "t.json")
        with structlog.testing.capture_logs() as logs:
            store.register(self.SECRET, scanned_text=self.TEXT)
        # Either guard may fire first; both must stay silent about the value.
        rejected = [
            e
            for e in logs
            if e.get("event")
            in ("taxonomy_value_like_category_rejected", "taxonomy_category_not_label_shaped")
        ]
        assert len(rejected) == 1
        # logging the value would just move the leak into the log file
        payload = json.dumps(logs).lower()
        assert self.SECRET.lower() not in payload
        assert "deploy password" not in payload

    def test_rejected_without_scanned_text_too(self, tmp_path):
        """The guard must not depend on the caller remembering to pass the text.

        This replaces an earlier test asserting the opposite — that a value-like
        category with no ``scanned_text`` coined and persisted "exactly as
        before". That was the weaker contract: it left every caller that omits
        the argument unprotected. The shape guard needs no text, so it holds
        here too.
        """
        path = tmp_path / "t.json"
        store = TaxonomyStore(path=path)
        assert store.register(self.SECRET) == GENERIC_PREFIX
        assert store.terms() == {}
        assert not path.exists()

    def test_label_shaped_terms_still_coin_without_scanned_text(self, tmp_path):
        """The actual back-compat concern: existing callers pass no text."""
        path = tmp_path / "t.json"
        store = TaxonomyStore(path=path)
        assert store.register("Employee ID") == "EMPLOYEE_ID"
        assert store.terms()
        assert path.exists()

    def test_genuine_label_absent_from_the_text_still_coins_and_persists(self, tmp_path):
        path = tmp_path / "t.json"
        store = TaxonomyStore(path=path)
        text = "my badge is EMP-4471 for the door"
        assert store.register("Employee ID", scanned_text=text) == "EMPLOYEE_ID"
        assert store.prefix_of("employee_id") == "EMPLOYEE_ID"
        assert path.exists()

    def test_rejection_is_case_insensitive(self, tmp_path):
        store = TaxonomyStore(path=tmp_path / "t.json")
        got = store.register("CorrectHorse", scanned_text="the password is correcthorse ok")
        assert got == GENERIC_PREFIX
        assert store.terms() == {}

    def test_rejection_sees_through_the_underscores_normalization_adds(self, tmp_path):
        store = TaxonomyStore(path=tmp_path / "t.json")
        got = store.register("correct_horse", scanned_text="the password is correcthorse ok")
        assert got == GENERIC_PREFIX
        assert store.terms() == {}

    def test_over_long_value_like_term_does_not_leak_into_a_derived_prefix(self, tmp_path):
        # The length bound alone returns _derive_prefix(term), which would put
        # the first MAX_PREFIX_LEN characters of the secret in the token: the
        # value-like guard has to run first.
        secret = "S3cr3tPassphraseNeverShareThisOneAnywhereAtAllEverPlease" * 2
        store = TaxonomyStore(path=tmp_path / "t.json")
        got = store.register(secret, scanned_text=f"pass = {secret} end")
        assert got == GENERIC_PREFIX
        assert secret[:8].upper() not in got

    def test_canonical_category_is_never_rejected(self, tmp_path):
        # "person" is a code-controlled label, not model-coined content: it must
        # keep its canonical prefix even when the word appears in the text.
        store = TaxonomyStore(path=tmp_path / "t.json")
        got = store.register("person", scanned_text="the person named Jane Doe")
        assert got == CANONICAL["person"]


class TestConcurrentPersistence:
    """Three processes ship (wedge, browser proxy, demo) and each holds its own
    TaxonomyStore over the same file. A whole-dict write of state read at
    construction makes the last writer silently discard the others' terms.
    """

    def test_two_stores_on_one_path_do_not_clobber_each_other(self, tmp_path):
        path = tmp_path / "t.json"
        a = TaxonomyStore(path=path)
        b = TaxonomyStore(path=path)  # constructed before either wrote
        a.register("alpha term")
        b.register("beta term")
        on_disk = json.loads(path.read_text(encoding="utf-8"))
        assert "alpha_term" in on_disk, f"first writer's term was clobbered: {on_disk}"
        assert "beta_term" in on_disk

    def test_an_existing_prefix_is_never_reassigned(self, tmp_path):
        path = tmp_path / "t.json"
        a = TaxonomyStore(path=path)
        b = TaxonomyStore(path=path)
        a.register("shared term")
        first = json.loads(path.read_text(encoding="utf-8"))["shared_term"]
        b.register("shared term")  # b never saw a's write
        assert json.loads(path.read_text(encoding="utf-8"))["shared_term"] == first
        assert b.prefix_of("shared_term") == first  # in-memory follows the disk

    def test_temp_path_is_unique_per_store(self, tmp_path):
        path = tmp_path / "t.json"
        a = TaxonomyStore(path=path)
        b = TaxonomyStore(path=path)
        assert a._tmp_path() != b._tmp_path()
        assert a._tmp_path() is not None

    def test_no_temp_file_survives_a_write(self, tmp_path):
        path = tmp_path / "t.json"
        TaxonomyStore(path=path).register("some coined term")
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != "t.json"]
        assert leftovers == []


class TestLabelShapeGuard:
    """Bypasses of the containment-only guard, proven against the first fix.

    Containment keys on the category echoing the prompt, so a model returning
    ``c = "password_" + t`` egressed the whole secret as
    ``[PASSWORD_TR0UB4DOR_3X_1]`` — the label and the value are not adjacent in
    the prompt, so nothing matched. Every case below reached the outbound token
    and ``taxonomy.json`` before the shape allowlist was added.
    """

    SECRET = "Tr0ub4dor&3x"
    TEXT = "my password is Tr0ub4dor&3x please rotate"

    @pytest.mark.parametrize(
        "coined",
        [
            "Tr0ub4dor&3x",  # the original issue #61 shape
            "password_Tr0ub4dor&3x",  # label-prefixed  -> was [PASSWORD_TR0UB4DOR_3X_1]
            "Tr0ub4dor&3x_password",  # label-suffixed
            "the Tr0ub4dor&3x",  # article-prefixed
            "Tr0ub4dor%263x",  # url-encoded
            "x3&rod4bu0rT",  # reversed, trivially invertible
            "547230756234646f72263378",  # hex-encoded
            "TTrr00uubb44ddoorr&&33xx",  # character-doubled
            "Txrx0xuxbx4xdxoxrx&x3xx",  # character-interleaved
            "AKIAIOSFODN7EXAMPLE",  # near-complete AWS key (one char dropped)
            "pin_4821",  # short numeric value wearing a label
        ],
    )
    def test_value_shaped_category_never_reaches_the_token(self, tmp_path, coined):
        store = TaxonomyStore(path=tmp_path / "t.json")
        assert store.register(coined, scanned_text=self.TEXT) == GENERIC_PREFIX

    def test_nothing_value_shaped_is_persisted(self, tmp_path):
        path = tmp_path / "t.json"
        store = TaxonomyStore(path=path)
        for coined in ("password_" + self.SECRET, "x3&rod4bu0rT", "pin_4821"):
            store.register(coined, scanned_text=self.TEXT)
        assert not path.exists(), "a value-shaped category was written to disk"

    def test_label_shaped_secret_present_in_the_text_is_still_caught(self, tmp_path):
        """Shape cannot see this one; containment is what rejects it."""
        store = TaxonomyStore(path=tmp_path / "t.json")
        assert store.register("hunter2", scanned_text="my password is hunter2 ok") == GENERIC_PREFIX

    @pytest.mark.parametrize(
        "label",
        [
            "employee_id",
            "badge_number",
            "oauth2_token",  # digits are fine when they trail a word
            "sha256_hash",
            "ipv4_address",
            "s3_bucket",
            "project_codename",
        ],
    )
    def test_genuine_labels_still_coin(self, tmp_path, label):
        store = TaxonomyStore(path=tmp_path / "t.json")
        assert store.register(label, scanned_text="an unrelated prompt") == label.upper()

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="POSIX mode bits: os.chmod on Windows only toggles the read-only flag, "
        "so st_mode stays 0o666. Access control there is ACL-based and not what "
        "this asserts.",
    )
    def test_persisted_file_is_not_world_readable(self, tmp_path):
        """Coined terms derive from prompts; 0644 let any local user read them."""
        path = tmp_path / "t.json"
        TaxonomyStore(path=path).register("employee_badge", scanned_text="unrelated")
        assert path.exists()
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def test_merge_never_creates_a_duplicate_prefix(tmp_path):
    """Two stores coining terms that truncate to the same prefix must not collide.

    taxonomy.py requires prefixes to be unique because a collision merges two
    categories' token counters — the reversible vault could then substitute the
    wrong original value back into a response. _unique_prefix_locked chose
    against local state only, and the on-disk map was folded in afterwards,
    which could reintroduce the duplicate.
    """
    path = tmp_path / "t.json"
    a, b = TaxonomyStore(path=path), TaxonomyStore(path=path)
    a.register("customer account reference number alpha")
    b.register("customer account reference number bravo")
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert len(on_disk) == 2, on_disk
    assert len(set(on_disk.values())) == 2, f"prefix collision on disk: {on_disk}"

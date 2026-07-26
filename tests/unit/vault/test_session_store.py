"""SessionStore: deterministic numbered tokens, per-category counters (M2/M3)."""

from __future__ import annotations

import threading

from domestique.vault.session import SessionStore


class TestNumberedTokens:
    def test_distinct_values_get_distinct_numbered_tokens(self) -> None:
        store = SessionStore()
        t1 = store.tokenize("123-45-6789", "SSN")
        t2 = store.tokenize("987-65-4321", "SSN")
        assert t1 == "[SSN_1]"
        assert t2 == "[SSN_2]"
        assert t1 != t2

    def test_same_value_returns_same_token(self) -> None:
        store = SessionStore()
        first = store.tokenize("a@b.com", "email")
        again = store.tokenize("a@b.com", "email")
        assert first == again == "[EMAIL_1]"

    def test_counters_are_per_category(self) -> None:
        store = SessionStore()
        assert store.tokenize("123-45-6789", "SSN") == "[SSN_1]"
        assert store.tokenize("a@b.com", "email") == "[EMAIL_1]"
        assert store.tokenize("555-123-4567", "phone") == "[PHONE_1]"

    def test_category_normalized_to_upper_prefix(self) -> None:
        store = SessionStore()
        assert store.tokenize("x", "aws_key") == "[AWS_KEY_1]"


class TestLookup:
    def test_lookup_returns_original(self) -> None:
        store = SessionStore()
        token = store.tokenize("123-45-6789", "SSN")
        assert store.lookup(token) == "123-45-6789"

    def test_lookup_unknown_token_returns_none(self) -> None:
        store = SessionStore()
        assert store.lookup("[SSN_9]") is None

    def test_entries_snapshot(self) -> None:
        store = SessionStore()
        store.tokenize("123-45-6789", "SSN")
        store.tokenize("a@b.com", "email")
        assert store.entries() == {"[SSN_1]": "123-45-6789", "[EMAIL_1]": "a@b.com"}

    def test_clear_empties_store(self) -> None:
        store = SessionStore()
        store.tokenize("123-45-6789", "SSN")
        store.clear()
        assert store.size == 0
        assert store.lookup("[SSN_1]") is None


class TestSessionCounterFloor:
    def test_counter_floor_reserves_low_numbers(self) -> None:
        """TokenService will pre-reserve pinned indices via set_counter_floor."""
        store = SessionStore()
        store.set_counter_floor("SSN", 3)
        assert store.tokenize("123-45-6789", "SSN") == "[SSN_4]"


class TestThreadSafety:
    def test_concurrent_tokenize_no_duplicate_tokens(self) -> None:
        store = SessionStore()
        tokens: list[str] = []
        lock = threading.Lock()

        def work(i: int) -> None:
            t = store.tokenize(f"value-{i}", "SSN")
            with lock:
                tokens.append(t)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(tokens)) == 100

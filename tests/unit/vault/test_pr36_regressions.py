"""Regression tests for the five bugs found in PR #36's review.

Each test reproduces the reported defect through a public API and asserts the
fixed behaviour. See the PR thread for the original end-to-end reproductions.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

from domestique.detectors.registry import _redact_text
from domestique.models import Detection, Span
from domestique.vault.pinned import PinnedVault
from domestique.vault.service import TokenService
from domestique.vault.session import MAX_TOKEN_LEN, SessionStore, category_prefix
from domestique.vault.stream import StreamDetokenizer


class FakeKeyProvider:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key if key is not None else os.urandom(32)

    def get_or_create_key(self) -> bytes | None:
        return self.key


def _service() -> TokenService:
    return TokenService(SessionStore(), None)


# --- Bug 1: overlapping detections must redact the union, never leak a prefix ---


class TestBug1OverlapUnion:
    def test_overlapping_spans_redact_union_no_prefix_leak(self) -> None:
        text = "my ssn is 123-45-6789"
        # Two detectors flag the same SSN with different left boundaries.
        dets = [
            Detection(detector="secrets", category="us_ssn", confidence=0.9,
                      span=Span(10, 21)),          # full "123-45-6789"
            Detection(detector="secrets", category="us_ssn", confidence=0.8,
                      span=Span(15, 21)),          # inner "5-6789"
        ]
        out, minted = _redact_text(text, dets, _service())
        assert "123-4" not in out  # the leaked prefix from the old drop logic
        assert "123-45-6789" not in out
        assert out == "my ssn is [SSN_1]"
        assert minted == {"[SSN_1]"}

    def test_pinned_prefix_of_email_does_not_leak(self) -> None:
        text = "email bob@acme.com"
        dets = [
            Detection(detector="secrets", category="email_address", confidence=0.9,
                      span=Span(6, 18)),           # "bob@acme.com"
            Detection(detector="pinned_vault", category="domain", confidence=1.0,
                      span=Span(10, 18)),          # pinned "acme.com"
        ]
        out, _ = _redact_text(text, dets, _service())
        assert "bob@" not in out
        assert "acme.com" not in out

    def test_disjoint_touching_spans_stay_separate(self) -> None:
        # Adjacent (end == next start) is NOT an overlap: two distinct secrets
        # must still get two distinct tokens (not merged into one).
        text = "AAAABBBB"
        svc = _service()
        dets = [
            Detection(detector="secrets", category="us_ssn", confidence=0.9,
                      span=Span(0, 4)),
            Detection(detector="secrets", category="us_ssn", confidence=0.9,
                      span=Span(4, 8)),
        ]
        out, minted = _redact_text(text, dets, svc)
        assert len(minted) == 2                      # two distinct tokens, not merged
        assert minted == {"[SSN_1]", "[SSN_2]"}
        # Both halves are fully covered and each round-trips to its own value.
        assert "A" not in out and "B" not in out
        restored, _ = svc.detokenize_text(out, allowed=minted)
        assert restored == "AAAABBBB"

    def test_zero_length_span_is_ignored(self) -> None:
        text = "clean text"
        dets = [Detection(detector="pipeline", category="detector_error",
                          confidence=1.0, span=Span(0, 0))]
        out, minted = _redact_text(text, dets, _service())
        assert out == text
        assert minted == set()


# --- Bug 2: category prefixes with ':'/space must sanitize and round-trip ---


class TestBug2CategorySanitize:
    def test_gliner_category_round_trips(self) -> None:
        svc = _service()
        token = svc.tokenize("Jane Doe", "pii:person")
        # "pii:" prefix normalizes to the canonical "person" category, which
        # now shares its token with plain "person" (GLiNER) — see taxonomy.py.
        assert token == "[PERSON_1]"
        restored, unknown = svc.detokenize_text(f"Contact {token}.")
        assert restored == "Contact Jane Doe."
        assert unknown == []

    def test_llm_category_with_space_round_trips(self) -> None:
        svc = _service()
        token = svc.tokenize("Acme Corp", "llm_classified:customer data")
        assert " " not in token and ":" not in token
        restored, unknown = svc.detokenize_text(f"from {token}")
        assert restored == "from Acme Corp"
        assert unknown == []

    def test_known_alias_and_plain_category_unaffected(self) -> None:
        assert category_prefix("us_ssn") == "SSN"
        assert category_prefix("codename") == "CODENAME"
        assert category_prefix("API_key") == "API_KEY"


# --- Bug 3: detokenization must be scoped to the current request's tokens ---


class TestBug3ConversationScope:
    def test_scoped_detok_ignores_other_conversations_token(self) -> None:
        svc = _service()
        # Conversation B mints its secret's token.
        tok_b = svc.tokenize("444-44-4444", "us_ssn")
        # Conversation A answered a request that minted NOTHING; A's reply
        # merely echoes B's token string.
        reply_a = f"as you said, {tok_b} — done"
        restored, unknown = svc.detokenize_text(reply_a, allowed=set())
        assert "444-44-4444" not in restored     # B's secret stays out of A
        assert tok_b in restored                  # echoed token left verbatim
        assert unknown == [tok_b]                 # and reported, not silent

    def test_scoped_detok_restores_own_tokens(self) -> None:
        svc = _service()
        tok = svc.tokenize("111-11-1111", "us_ssn")
        restored, unknown = svc.detokenize_text(f"here: {tok}", allowed={tok})
        assert restored == "here: 111-11-1111"
        assert unknown == []

    def test_stream_detokenizer_respects_scope(self) -> None:
        svc = _service()
        tok_b = svc.tokenize("444-44-4444", "us_ssn")
        st = StreamDetokenizer(svc, allowed=set())
        out = st.feed(f"echo {tok_b}") + st.flush()
        assert "444-44-4444" not in out
        assert tok_b in out


# --- Bug 4: PinnedVault must be thread-safe under concurrent pins/reads ---


class TestBug4VaultConcurrency:
    def test_concurrent_pins_and_reads_no_exceptions_no_lost_writes(
        self, tmp_path: Path
    ) -> None:
        provider = FakeKeyProvider()
        vault = PinnedVault(tmp_path / "vault.bin", provider)
        vault.load()
        assert vault.available

        errors: list[BaseException] = []
        n_writers, per_writer = 12, 40

        def writer(base: int) -> None:
            try:
                for i in range(per_writer):
                    vault.pin(f"val-{base}-{i}", "us_ssn")
            except BaseException as exc:  # noqa: BLE001 - capture races for assert
                errors.append(exc)

        def reader() -> None:
            try:
                for _ in range(400):
                    vault.values()
                    vault.max_index("us_ssn")
                    vault.lookup_token("[SSN_1]")
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(w,)) for w in range(n_writers)]
        threads += [threading.Thread(target=reader) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"races raised: {errors[:3]}"
        expected = n_writers * per_writer
        assert len(vault.values()) == expected      # no lost writes in memory

        # And the persisted file agrees after a reload (durability).
        reloaded = PinnedVault(tmp_path / "vault.bin", provider)
        reloaded.load()
        assert len(reloaded.values()) == expected


# --- Bug 5: minted tokens must never exceed MAX_TOKEN_LEN ---


class TestBug5TokenLength:
    def test_long_unaliased_category_is_length_bounded(self) -> None:
        svc = _service()
        token = svc.tokenize("some-id", "medical_record_identifier_number_extended")
        assert len(token) <= MAX_TOKEN_LEN
        # And it still round-trips (grammar-valid, bounded).
        restored, unknown = svc.detokenize_text(f"id {token}", allowed={token})
        assert restored == "id some-id"
        assert unknown == []

    def test_streaming_equals_nonstreaming_for_bounded_long_token(self) -> None:
        svc = _service()
        token = svc.tokenize("some-id", "medical_record_identifier_number_extended")
        reply = f"The record is {token} on file."
        expected, _ = svc.detokenize_text(reply, allowed={token})
        # Split at every offset; streamed reassembly must match non-streaming.
        for cut in range(len(reply) + 1):
            st = StreamDetokenizer(svc, allowed={token})
            streamed = st.feed(reply[:cut]) + st.feed(reply[cut:]) + st.flush()
            assert streamed == expected, f"mismatch at cut={cut}"


# --- Loop 3 regressions: session/pinned counter coordination ---


def _vault_service(tmp_path: Path) -> TokenService:
    vault = PinnedVault(tmp_path / "vault.bin", FakeKeyProvider())
    vault.load()
    return TokenService(SessionStore(), vault)


class TestCategoryPrefixIdempotent:
    def test_prefix_truncation_does_not_break_idempotence(self) -> None:
        # A category whose sanitized form is longer than MAX_PREFIX_LEN and
        # whose truncation boundary lands on a "_". category_prefix must be a
        # fixed point, or sync_counter_floors keys the floor differently from
        # the session counter and the collision re-opens.
        long_cat = "a" * 22 + "_bb"           # -> "AAA…(22)_" before rstrip
        p = category_prefix(long_cat)
        assert not p.endswith("_")
        assert category_prefix(p) == p          # idempotent
        realistic = "llm_classified:medical patient identifier"
        r = category_prefix(realistic)
        assert not r.endswith("_")
        assert category_prefix(r) == r

    def test_long_category_pinned_and_session_do_not_collide(self, tmp_path: Path) -> None:
        # Regression for the non-idempotence leak: a pinned token and a
        # session token of the same long category must get distinct tokens,
        # and each must reverse to its own value.
        cat = "llm_classified:medical patient identifier"
        svc = _vault_service(tmp_path)
        assert svc.pinned is not None
        pin_tok = svc.pin("pinned-secret", cat)
        # Rebuild a service over the SAME vault (as a fresh process would):
        # construction floors the session above the pinned index.
        svc2 = TokenService(SessionStore(), svc.pinned)
        sess_tok = svc2.session.tokenize("session-secret", cat)
        assert pin_tok != sess_tok
        assert svc2.detokenize_text(pin_tok, allowed={pin_tok})[0] == "pinned-secret"
        assert svc2.detokenize_text(sess_tok, allowed={sess_tok})[0] == "session-secret"


class TestPinAfterMintNoCollision:
    def test_runtime_pin_reserves_index_above_session(self, tmp_path: Path) -> None:
        svc = _vault_service(tmp_path)
        a = svc.session.tokenize("val-A", "us_ssn")   # [SSN_1]
        b = svc.session.tokenize("val-B", "us_ssn")   # [SSN_2]
        v = svc.session.tokenize("val-V", "us_ssn")   # [SSN_3]
        assert (a, b, v) == ("[SSN_1]", "[SSN_2]", "[SSN_3]")

        # Pinning val-V at runtime must NOT reuse [SSN_1] (which already maps
        # to val-A in the session) — it must land above the session max.
        pin_tok = svc.pin("val-V", "us_ssn")
        assert pin_tok not in {a, b, v}
        assert pin_tok == "[SSN_4]"

        # [SSN_1] still resolves to val-A (not the pinned val-V): no wrong
        # reversal.
        assert svc.detokenize_text(a, allowed={a})[0] == "val-A"
        # The new pinned token resolves to val-V.
        assert svc.detokenize_text(pin_tok, allowed={pin_tok})[0] == "val-V"

        # Future session tokens stay clear of the new pinned index.
        nxt = svc.session.tokenize("val-W", "us_ssn")
        assert nxt not in {a, b, v, pin_tok}
        assert nxt == "[SSN_5]"

    def test_pin_is_noop_without_vault(self) -> None:
        assert _service().pin("x", "us_ssn") == ""

    def test_pin_and_racing_tokenize_never_collide_on_index(
        self, tmp_path: Path, monkeypatch: object
    ) -> None:
        """Regression: TokenService.pin()'s floor-compute-then-reserve used to
        be two separate lock acquisitions (its own read, then PinnedVault's
        internal one) with a gap in between. A tokenize() for the same
        category landing in that gap could mint a session token at the exact
        index pin() was about to claim -- since detokenize_text resolves
        session-first, the pinned value would become unreachable, silently
        defeating the pin.

        Real thread scheduling almost never lands in that few-bytecode gap,
        so this forces the exact interleaving deterministically: pin() is
        paused right after entering PinnedVault.pin() (i.e. after its floor
        was already computed), a concurrent tokenize() for the same category
        is given a chance to run, and only then is pin() allowed to finish
        reserving. Under the fix, tokenize() shares TokenService._lock with
        pin() and cannot run until pin() fully releases it, so it always
        lands *after* the reservation, not inside its gap.
        """
        svc = _vault_service(tmp_path)
        assert svc.pinned is not None
        entered_pinned_pin = threading.Event()
        tokenize_attempted = threading.Event()
        original_pinned_pin = svc.pinned.pin

        def instrumented_pinned_pin(value: str, category: str, min_index: int = 1) -> str:
            entered_pinned_pin.set()
            # Under the bug this window is where a racing tokenize() mints
            # into the floor pin() is about to claim; under the fix,
            # tokenize() is blocked on TokenService._lock and can't even
            # start until this call (and pin()'s whole critical section)
            # returns, so this wait always times out harmlessly.
            tokenize_attempted.wait(timeout=0.2)
            return original_pinned_pin(value, category, min_index=min_index)

        monkeypatch.setattr(svc.pinned, "pin", instrumented_pinned_pin)

        result: dict[str, str] = {}

        def run_pin() -> None:
            result["pin_token"] = svc.pin("pinned-val", "us_ssn")

        def run_tokenize() -> None:
            entered_pinned_pin.wait(timeout=1.0)
            result["session_token"] = svc.tokenize("session-val", "us_ssn")
            tokenize_attempted.set()

        t_pin = threading.Thread(target=run_pin)
        t_tok = threading.Thread(target=run_tokenize)
        t_pin.start()
        t_tok.start()
        t_pin.join(timeout=2.0)
        t_tok.join(timeout=2.0)

        assert not t_pin.is_alive() and not t_tok.is_alive(), "test threads did not finish"
        assert result["pin_token"] and result["session_token"]
        assert result["pin_token"] != result["session_token"], (
            "pin() and a racing tokenize() minted the same token for two different values"
        )
        # The concrete symptom a collision produces: each token must still
        # reverse to the value it was actually minted for.
        pinned_restored, _ = svc.detokenize_text(
            result["pin_token"], allowed={result["pin_token"]}
        )
        assert pinned_restored == "pinned-val"
        session_restored, _ = svc.detokenize_text(
            result["session_token"], allowed={result["session_token"]}
        )
        assert session_restored == "session-val"

"""StreamDetokenizer: chunk-boundary-safe inline detokenization (M5, M8).

The core property: for ANY way a text is split into chunks, feeding the
chunks and flushing must produce byte-identical output to non-streaming
detokenization — including tokens split mid-``[SSN_…``.
"""

from __future__ import annotations

import random

import pytest

from domestique.vault.service import TokenService
from domestique.vault.session import SessionStore
from domestique.vault.stream import StreamDetokenizer


@pytest.fixture
def service() -> TokenService:
    svc = TokenService(SessionStore(), None)
    svc.tokenize("123-45-6789", "SSN")
    svc.tokenize("987-65-4321", "SSN")
    svc.tokenize("a@b.com", "email")
    return svc


CORPUS = [
    "Call [SSN_1] now",
    "[SSN_1] and [SSN_2] differ",
    "adjacent [SSN_1][EMAIL_1] tokens",
    "unknown [SSN_9] stays; known [SSN_2] goes",
    "bracket alone [ and [not_a_token] and trailing [",
    "ends with token [EMAIL_1]",
    "[SSN_1]",
    "no tokens at all here",
    "half [SSN and done",
    "double [[SSN_1]] brackets",
]


def _reference(service: TokenService, text: str) -> str:
    out, _ = service.detokenize_text(text)
    return out


class TestSplitFuzz:
    def test_every_two_way_split_matches_reference(self, service: TokenService) -> None:
        for text in CORPUS:
            expected = _reference(service, text)
            for i in range(len(text) + 1):
                st = StreamDetokenizer(service)
                got = st.feed(text[:i]) + st.feed(text[i:]) + st.flush()
                assert got == expected, f"split at {i} of {text!r}"

    def test_random_multiway_splits_match_reference(self, service: TokenService) -> None:
        rng = random.Random(42)
        for text in CORPUS:
            expected = _reference(service, text)
            for _ in range(25):
                st = StreamDetokenizer(service)
                out: list[str] = []
                pos = 0
                while pos < len(text):
                    step = rng.randint(1, 5)
                    out.append(st.feed(text[pos : pos + step]))
                    pos += step
                out.append(st.flush())
                assert "".join(out) == expected, f"multiway split of {text!r}"

    def test_char_by_char_streaming(self, service: TokenService) -> None:
        text = "Contact [EMAIL_1] re [SSN_1] or [SSN_9]"
        expected = _reference(service, text)
        st = StreamDetokenizer(service)
        got = "".join(st.feed(c) for c in text) + st.flush()
        assert got == expected


class TestHoldbackBounds:
    def test_holdback_never_exceeds_32_chars(self, service: TokenService) -> None:
        st = StreamDetokenizer(service)
        for chunk in ("x" * 10, "[SSN", "_", "1", "y" * 50, "[" + "A" * 40):
            st.feed(chunk)
            assert len(st.held) <= 32

    def test_flush_emits_partial_token_verbatim(self, service: TokenService) -> None:
        st = StreamDetokenizer(service)
        out = st.feed("tail [SSN_")
        assert out == "tail "
        assert st.flush() == "[SSN_"

    def test_plain_text_never_held_back(self, service: TokenService) -> None:
        st = StreamDetokenizer(service)
        assert st.feed("hello world, no brackets") == "hello world, no brackets"
        assert st.held == ""


class TestUnknownTokens:
    def test_unknown_tokens_pass_through_and_are_recorded(self, service: TokenService) -> None:
        st = StreamDetokenizer(service)
        out = st.feed("[SSN_9] then [SSN_1]") + st.flush()
        assert out == "[SSN_9] then 123-45-6789"
        assert st.unknown_tokens == ["[SSN_9]"]

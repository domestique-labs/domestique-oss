from pathlib import Path

from bench.eval.corpus import CorpusRow, corpus_checksum, load_corpus

DATA = Path(__file__).parent.parent.parent / "bench" / "eval" / "data" / "corpus.jsonl"


def test_load_corpus_parses_rows():
    rows = load_corpus(DATA)
    assert len(rows) >= 12
    assert all(isinstance(r, CorpusRow) for r in rows)
    assert all(r.expected_action in {"allow", "redact", "block"} for r in rows)
    assert len({r.id for r in rows}) == len(rows)  # ids unique


def test_checksum_is_stable_and_order_independent():
    rows = load_corpus(DATA)
    assert corpus_checksum(rows) == corpus_checksum(list(reversed(rows)))
    assert len(corpus_checksum(rows)) == 64  # sha256 hex


def test_load_rejects_bad_action(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"id": "x", "text": "hi", "expected_action": "nope"}\n', encoding="utf-8")
    try:
        load_corpus(bad)
        assert False, "expected ValueError"
    except ValueError:
        pass

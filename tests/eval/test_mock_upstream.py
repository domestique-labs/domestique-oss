import httpx

from bench.eval.mock_upstream import running_mock


def test_mock_records_body_and_returns_openai_shape():
    with running_mock() as handle:
        r = httpx.post(
            f"{handle.base_url}/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi there"}]},
            timeout=5,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["choices"][0]["message"]["role"] == "assistant"
        assert handle.mock.received[-1]["messages"][-1]["content"] == "hi there"

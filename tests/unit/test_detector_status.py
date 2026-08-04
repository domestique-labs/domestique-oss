"""Tests for the startup detector-availability probe (UX-2 fail-loud/strict)."""

from __future__ import annotations

from domestique.config import Settings
from domestique.detectors import status as st


def test_pii_unavailable_when_module_missing(monkeypatch) -> None:
    monkeypatch.setattr(st, "_module_available", lambda name: False)
    settings = Settings(enable_pii_detection=True)
    pii = next(s for s in st.detector_status(settings) if s.key == "pii")
    assert pii.configured is True
    assert pii.available is False
    assert "pii" in pii.install_hint.lower()


def test_pii_not_configured_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(st, "_module_available", lambda name: True)
    settings = Settings(enable_pii_detection=False)
    pii = next(s for s in st.detector_status(settings) if s.key == "pii")
    assert pii.configured is False
    assert pii.available is False


def test_available_when_module_present(monkeypatch) -> None:
    monkeypatch.setattr(st, "_module_available", lambda name: True)
    settings = Settings(enable_pii_detection=True)
    pii = next(s for s in st.detector_status(settings) if s.key == "pii")
    assert pii.available is True


def test_unavailable_configured_filters_to_broken_tiers(monkeypatch) -> None:
    # gliner present, presidio missing
    monkeypatch.setattr(st, "_module_available", lambda name: name != "presidio_analyzer")
    settings = Settings(enable_pii_detection=True, enable_gliner=True)
    missing = st.unavailable_configured(st.detector_status(settings))
    assert {m.key for m in missing} == {"pii"}


class TestLocalLLMTier:
    """The one tier with no importable module: it needs a daemon probe."""

    def _status(self, settings: Settings, *, deep: bool = False) -> st.TierStatus:
        return next(s for s in st.detector_status(settings, deep=deep) if s.key == "local_llm")

    def test_disabled_by_default_and_never_probed(self, monkeypatch) -> None:
        def _boom(base: str, timeout: float) -> set[str]:
            raise AssertionError("probed a tier that is switched off")

        monkeypatch.setattr(st, "_ollama_tags", _boom)
        s = self._status(Settings())
        assert s.configured is False
        assert s.available is False

    def test_available_when_daemon_serves_the_configured_model(self, monkeypatch) -> None:
        settings = Settings(enable_local_llm=True)
        monkeypatch.setattr(st, "_ollama_tags", lambda base, timeout: {settings.local_llm_model})
        s = self._status(settings)
        assert s.configured is True
        assert s.available is True
        assert s.detail == ""

    def test_unreachable_daemon_reported_distinctly(self, monkeypatch) -> None:
        monkeypatch.setattr(st, "_ollama_tags", lambda base, timeout: None)
        s = self._status(Settings(enable_local_llm=True))
        assert s.available is False
        assert "reach" in s.detail.lower()

    def test_missing_model_reported_distinctly(self, monkeypatch) -> None:
        settings = Settings(enable_local_llm=True)
        monkeypatch.setattr(st, "_ollama_tags", lambda base, timeout: {"some-other-model:1b"})
        s = self._status(settings)
        assert s.available is False
        assert settings.local_llm_model in s.detail
        assert "reach" not in s.detail.lower(), "must not blame the daemon for a missing model"

    def test_untagged_model_matches_the_latest_tag(self, monkeypatch) -> None:
        settings = Settings(enable_local_llm=True, local_llm_model="qwen3")
        monkeypatch.setattr(st, "_ollama_tags", lambda base, timeout: {"qwen3:latest"})
        assert self._status(settings).available is True

    def test_probe_failure_degrades_and_never_raises(self, monkeypatch) -> None:
        def _boom(base: str, timeout: float) -> set[str]:
            raise OSError("network is down")

        monkeypatch.setattr(st, "_ollama_tags", _boom)
        s = self._status(Settings(enable_local_llm=True))
        assert s.available is False
        assert s.detail  # says something, rather than exploding on the demo path

    def test_local_llm_leaks_into_unavailable_only_when_enabled(self, monkeypatch) -> None:
        monkeypatch.setattr(st, "_module_available", lambda name: name != "presidio_analyzer")
        monkeypatch.setattr(st, "_ollama_tags", lambda base, timeout: None)
        settings = Settings(enable_pii_detection=True, enable_gliner=True, enable_local_llm=True)
        missing = st.unavailable_configured(st.detector_status(settings))
        assert {m.key for m in missing} == {"pii", "local_llm"}


class TestOllamaTagsProbe:
    """The lifted `detect_existing_ollama_models` had two defects: a hardcoded
    localhost:11434, and no proxy bypass — so with the wedge/mitm proxy active
    the probe answered from the proxy, not the daemon."""

    def _fake_opener(self, monkeypatch, payload: bytes) -> dict[str, object]:
        import urllib.request

        seen: dict[str, object] = {}

        class _Resp:
            """Behaves like a real stream: honours a size arg, then EOFs.

            The previous version ignored the argument and returned the whole
            payload on every call, so it could not model a bounded read.
            """

            _remaining = payload

            def read(self, size: int | None = None) -> bytes:
                if size is None:
                    chunk, self._remaining = self._remaining, b""
                    return chunk
                chunk, self._remaining = self._remaining[:size], self._remaining[size:]
                return chunk

            def __enter__(self) -> _Resp:
                return self

            def __exit__(self, *exc: object) -> None:
                return None

        class _Opener:
            def open(self, req, timeout=None):  # noqa: ANN001, ANN202
                seen["url"] = req.full_url
                seen["timeout"] = timeout
                return _Resp()

        def _build_opener(*handlers):  # noqa: ANN002, ANN202
            seen["handlers"] = handlers
            return _Opener()

        monkeypatch.setattr(urllib.request, "build_opener", _build_opener)
        return seen

    def test_honours_configured_url_and_bypasses_the_proxy(self, monkeypatch) -> None:
        import urllib.request

        seen = self._fake_opener(monkeypatch, b'{"models": [{"name": "m:1b"}]}')
        names = st._ollama_tags("http://127.0.0.1:9999", 1.0)
        assert names == {"m:1b"}
        assert seen["url"] == "http://127.0.0.1:9999/api/tags"
        handlers = seen["handlers"]
        assert any(isinstance(h, urllib.request.ProxyHandler) for h in handlers)  # type: ignore[union-attr]
        proxy = next(h for h in handlers if isinstance(h, urllib.request.ProxyHandler))  # type: ignore[union-attr]
        assert proxy.proxies == {}, "system proxy not bypassed; an active wedge would answer"

    def test_unreachable_returns_none(self, monkeypatch) -> None:
        import urllib.request

        def _build_opener(*handlers):  # noqa: ANN002, ANN202
            raise OSError("connection refused")

        monkeypatch.setattr(urllib.request, "build_opener", _build_opener)
        assert st._ollama_tags("http://127.0.0.1:9999", 1.0) is None

    def test_non_http_url_is_refused(self, monkeypatch) -> None:  # noqa: ANN001
        """The URL must be rejected before any opener runs.

        Asserting only ``is None`` did not test the guard: without it,
        ``file://`` is opened and read, and the call still returns None simply
        because /etc/passwd is not JSON. A file:// directory serving
        Ollama-shaped JSON at api/tags was read straight off disk. So assert the
        opener is never built.
        """

        import urllib.request

        def _must_not_run(*_a: object, **_k: object) -> object:
            raise AssertionError("a non-http URL reached the opener")

        monkeypatch.setattr(urllib.request, "build_opener", _must_not_run)
        for url in ("file:///etc/passwd", "ftp://x/y", "gopher://x", "", "localhost:11434"):
            assert st._ollama_tags(url, 1.0) is None

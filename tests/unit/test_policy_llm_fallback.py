from pathlib import Path

from domestique.models import Action, Detection, Span
from domestique.policy import PolicyEngine

_CLI = Path("domestique/policy/cli-rules.yaml")
_BROWSER = Path("domestique/policy/browser-rules.yaml")


def _det(detector, category, conf):
    return Detection(detector=detector, category=category, confidence=conf, span=Span(0, 5))


def test_llm_coined_term_redacts():
    engine = PolicyEngine.from_yaml(_CLI)
    action = engine.evaluate([_det("local_llm_classifier", "employee_badge", 0.9)])
    assert action is Action.REDACT


def test_llm_below_threshold_allows():
    engine = PolicyEngine.from_yaml(_CLI)
    action = engine.evaluate([_det("local_llm_classifier", "employee_badge", 0.5)])
    assert action is Action.ALLOW


def test_canonical_pii_still_redacts():
    engine = PolicyEngine.from_yaml(_CLI)
    action = engine.evaluate([_det("gliner_ner", "email_address", 0.9)])
    assert action is Action.REDACT


def test_browser_blocks_llm_coined_term():
    assert (
        PolicyEngine.from_yaml(_BROWSER).evaluate(
            [_det("local_llm_classifier", "employee_badge", 0.9)]
        )
        is Action.BLOCK
    )


def test_browser_llm_below_block_threshold_redacts_rather_than_allowing():
    # Below the 0.8 block floor the browser must still not send cleartext: the
    # detector emits from 0.7 and the CLI redacts there, so allowing here leaked
    # on one surface what the other protected.
    assert (
        PolicyEngine.from_yaml(_BROWSER).evaluate(
            [_det("local_llm_classifier", "employee_badge", 0.75)]
        )
        is Action.REDACT
    )


def test_browser_blocks_canonical_pii():
    assert (
        PolicyEngine.from_yaml(_BROWSER).evaluate([_det("gliner_ner", "email_address", 0.9)])
        is Action.BLOCK
    )


class TestSurfacesAgreeOnTheLLMFloor:
    """The same detector must not be redacted on one surface and leaked on the other.

    The LLM tier emits at >= 0.7 and cli-rules redacts from 0.7, but browser-rules
    only blocked from 0.8 - so [0.7, 0.8) matched no browser rule and went out in
    cleartext. Both surfaces must act on every finding the detector emits.
    """

    def _engines(self):
        from pathlib import Path

        from domestique.policy import PolicyEngine

        base = Path("domestique/policy")
        return (
            PolicyEngine.from_yaml(base / "cli-rules.yaml"),
            PolicyEngine.from_yaml(base / "browser-rules.yaml"),
        )

    def _det(self, confidence):
        from domestique.models import Detection, Span

        return [
            Detection(
                detector="local_llm_classifier",
                category="person",
                confidence=confidence,
                span=Span(0, 5),
            )
        ]

    def test_neither_surface_allows_a_finding_the_detector_emitted(self):
        from domestique.models import Action

        cli, browser = self._engines()
        for confidence in (0.70, 0.75, 0.79, 0.80, 0.95):
            for name, engine in (("cli", cli), ("browser", browser)):
                action, _ = engine.explain(self._det(confidence))
                assert action is not Action.ALLOW, (
                    f"{name} allows an LLM finding at {confidence} in cleartext"
                )

    def test_browser_still_blocks_at_the_high_band(self):
        from domestique.models import Action

        _, browser = self._engines()
        assert browser.explain(self._det(0.85))[0] is Action.BLOCK

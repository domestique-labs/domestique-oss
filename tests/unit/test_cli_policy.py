from __future__ import annotations

import asyncio
from pathlib import Path

from domestique.config import Settings
from domestique.detectors.registry import DetectorPipeline, build_detectors
from domestique.models import Action
from domestique.policy import PolicyEngine

_CLI = Path("domestique/policy/cli-rules.yaml")


def _pipeline() -> DetectorPipeline:
    settings = Settings()
    return DetectorPipeline(build_detectors(settings), PolicyEngine.from_yaml(_CLI))


def test_wedge_policy_file_exists():
    assert _CLI.exists()


def test_aws_access_key_is_redacted_not_blocked():
    pipe = _pipeline()
    text = "my key is AKIAIOSFODNN7EXAMPLE and thats it"
    result = asyncio.run(pipe.inspect(text))
    assert result.action is Action.REDACT
    assert result.redacted_text is not None
    assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text


def test_private_key_is_blocked():
    pipe = _pipeline()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
    result = asyncio.run(pipe.inspect(text))
    assert result.action is Action.BLOCK

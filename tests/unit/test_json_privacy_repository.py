"""JsonPrivacyRepository 合并写入测试。"""

import json

import pytest
from pydantic import ValidationError

from privacyguard import PrivacyGuard
from privacyguard.api.errors import InvalidConfigurationError
from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.json_privacy_repository import (
    DEFAULT_PRIVACY_REPOSITORY_PATH,
    InvalidPrivacyRepositoryError,
    JsonPrivacyRepository,
    parse_privacy_repository_document,
)


def test_write_privacy_repository_requires_rule_based_detector() -> None:
    class _NonRuleDetector:
        pass

    guard = PrivacyGuard(detector=_NonRuleDetector(), decision_mode="label_only")
    with pytest.raises(InvalidConfigurationError):
        guard.write_privacy_repository({"true_personas": []})


def test_write_privacy_repository_accepts_true_personas(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    guard = PrivacyGuard(
        detector_mode="rule_based",
        decision_mode="label_only",
        detector_config={"privacy_repository_path": str(repo_path)},
    )

    summary = guard.write_privacy_repository(
        {
            "true_personas": [
                {
                    "persona_id": "real_001",
                    "slots": {
                        "name": {"value": "张三", "aliases": ["老张"]},
                    },
                }
            ],
        }
    )

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    assert summary["status"] == "ok"
    assert "version" not in stored
    assert stored["true_personas"][0]["persona_id"] == "real_001"
    names = [entry.value for entry in guard.detector.dictionary.get(PIIAttributeType.NAME, [])]
    assert "张三" in names


def test_write_privacy_repository_rejects_legacy_flat_payload() -> None:
    guard = PrivacyGuard(detector_mode="rule_based", decision_mode="label_only")
    with pytest.raises(ValidationError):
        guard.write_privacy_repository({"name": ["张三"]})


def test_write_privacy_repository_rejects_top_level_version_field() -> None:
    guard = PrivacyGuard(detector_mode="rule_based", decision_mode="label_only")
    with pytest.raises(ValidationError):
        guard.write_privacy_repository({"version": 2, "true_personas": []})


def test_parse_privacy_repository_document_rejects_top_level_version() -> None:
    with pytest.raises(InvalidPrivacyRepositoryError):
        parse_privacy_repository_document({"version": 2, "true_personas": []})


def test_write_privacy_repository_preserves_explicit_persona_id_that_looks_like_legacy_pattern(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    guard = PrivacyGuard(
        detector_mode="rule_based",
        decision_mode="label_only",
        detector_config={"privacy_repository_path": str(repo_path)},
    )

    guard.write_privacy_repository(
        {
            "true_personas": [
                {
                    "persona_id": "legacy-name-1",
                    "slots": {
                        "name": {"value": "张三", "aliases": ["老张"]},
                    },
                }
            ],
        }
    )

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    assert stored["true_personas"][0]["persona_id"] == "legacy-name-1"


def test_json_privacy_repository_repeated_same_persona_writes_do_not_duplicate_rows(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    repository = JsonPrivacyRepository(path=str(repo_path))

    patch = {
        "true_personas": [
            {
                "persona_id": "p_name",
                "metadata": {"legacy_source_slot": "name"},
                "slots": {"name": {"value": "张三", "aliases": []}},
            }
        ],
    }
    repository.merge_and_write(patch)
    repository.merge_and_write(patch)

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    assert len(stored["true_personas"]) == 1
    assert stored["true_personas"][0]["slots"]["name"]["value"] == "张三"


def test_json_privacy_repository_merges_conflicting_name_on_same_persona(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    repository = JsonPrivacyRepository(path=str(repo_path))
    repository.merge_and_write(
        {
            "true_personas": [
                {"persona_id": "friend_1", "slots": {"name": {"value": "Alice", "aliases": []}}},
            ],
        }
    )

    repository.merge_and_write(
        {
            "true_personas": [
                {"persona_id": "friend_1", "slots": {"name": {"value": "Bob", "aliases": []}}},
            ],
        }
    )

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    persona = stored["true_personas"][0]
    assert persona["persona_id"] == "friend_1"
    assert persona["slots"]["name"] == {"value": "Alice", "aliases": ["Bob"]}


def test_json_privacy_repository_merge_adds_phone_to_existing_persona(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    repository = JsonPrivacyRepository(path=str(repo_path))
    repository.merge_and_write(
        {
            "true_personas": [
                {
                    "persona_id": "dup",
                    "slots": {
                        "name": {"value": "Alice", "aliases": []},
                    },
                },
            ],
        }
    )

    repository.merge_and_write(
        {
            "true_personas": [
                {
                    "persona_id": "dup",
                    "slots": {"phone": {"value": "111", "aliases": []}},
                },
            ],
        }
    )

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    assert len(stored["true_personas"]) == 1
    persona = stored["true_personas"][0]
    assert persona["slots"]["name"] == {"value": "Alice", "aliases": []}
    assert persona["slots"]["phone"] == {"value": "111", "aliases": []}


def test_json_privacy_repository_write_merge_and_reload_detector(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    repo_path = tmp_path / DEFAULT_PRIVACY_REPOSITORY_PATH
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    repo_path.write_text(
        json.dumps(
            {
                "true_personas": [
                    {"persona_id": "old", "slots": {"name": {"value": "旧名", "aliases": []}}},
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    guard = PrivacyGuard(
        detector_mode="rule_based",
        decision_mode="label_only",
        detector_config={"privacy_repository_path": str(repo_path)},
    )
    guard.write_privacy_repository(
        {
            "true_personas": [
                {"persona_id": "new", "slots": {"name": {"value": "新名", "aliases": []}}},
            ],
        }
    )

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    assert "version" not in stored
    assert [persona["slots"]["name"]["value"] for persona in stored["true_personas"]] == ["旧名", "新名"]

    assert (
        guard.write_privacy_repository(
            {
                "true_personas": [
                    {"persona_id": "new", "slots": {"phone": {"value": "13900000000", "aliases": []}}},
                ],
            }
        )["status"]
        == "ok"
    )
    phones = [e.value for e in guard.detector.dictionary.get(PIIAttributeType.PHONE, [])]
    assert "13900000000" in phones

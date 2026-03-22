"""JsonPrivacyRepository 合并写入测试。"""

import json

import pytest

from privacyguard import PrivacyGuard
from privacyguard.api.errors import InvalidConfigurationError
from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.json_privacy_repository import (
    DEFAULT_PRIVACY_REPOSITORY_PATH,
    JsonPrivacyRepository,
    merge_privacy_documents,
)


def test_write_privacy_repository_requires_rule_based_detector() -> None:
    class _NonRuleDetector:
        pass

    guard = PrivacyGuard(detector=_NonRuleDetector(), decision_mode="label_only")
    with pytest.raises(InvalidConfigurationError):
        guard.write_privacy_repository({"name": ["x"]})


def test_merge_privacy_documents_dedupes_and_extends() -> None:
    base = {"name": ["张三"], "phone": ["100"]}
    patch = {"name": ["张三", "李四"], "phone": "200"}
    merged = merge_privacy_documents(base, patch)
    assert merged["name"] == ["张三", "李四"]
    assert merged["phone"] == ["100", "200"]


def test_merge_entities_by_entity_id() -> None:
    base = {
        "entities": [
            {"entity_id": "a", "name": ["王五"], "phone": ["111"]},
        ]
    }
    patch = {"entities": [{"entity_id": "a", "name": ["王小五"], "email": ["a@x.com"]}]}
    merged = merge_privacy_documents(base, patch)
    assert len(merged["entities"]) == 1
    ent = merged["entities"][0]
    assert ent["entity_id"] == "a"
    assert ent["name"] == ["王五", "王小五"]
    assert ent["phone"] == ["111"]
    assert ent["email"] == ["a@x.com"]


def test_write_privacy_repository_accepts_v2_true_personas(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    guard = PrivacyGuard(
        detector_mode="rule_based",
        decision_mode="label_only",
        detector_config={"privacy_repository_path": str(repo_path)},
    )

    summary = guard.write_privacy_repository(
        {
            "version": 2,
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
    assert stored["version"] == 2
    assert stored["true_personas"][0]["persona_id"] == "real_001"
    names = [entry.value for entry in guard.detector.dictionary.get(PIIAttributeType.NAME, [])]
    assert "张三" in names


def test_write_privacy_repository_preserves_explicit_v2_persona_id_that_looks_like_legacy_pattern(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    guard = PrivacyGuard(
        detector_mode="rule_based",
        decision_mode="label_only",
        detector_config={"privacy_repository_path": str(repo_path)},
    )

    guard.write_privacy_repository(
        {
            "version": 2,
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


def test_json_privacy_repository_repeated_legacy_flat_writes_do_not_duplicate_true_personas(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    repository = JsonPrivacyRepository(path=str(repo_path))

    repository.merge_and_write({"name": ["张三"]})
    repository.merge_and_write({"name": ["张三"]})

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    names = [
        persona["slots"]["name"]["value"]
        for persona in stored["true_personas"]
        if "name" in persona.get("slots", {})
    ]
    assert stored["version"] == 2
    assert names == ["张三"]


def test_json_privacy_repository_merges_conflicting_same_entity_slot_values_without_data_loss(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    repository = JsonPrivacyRepository(path=str(repo_path))
    repo_path.write_text(
        json.dumps(
            {
                "entities": [
                    {"entity_id": "friend_1", "name": ["Alice"]},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repository.merge_and_write({"entities": [{"entity_id": "friend_1", "name": ["Bob"]}]})

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    persona = stored["true_personas"][0]
    assert persona["persona_id"] == "friend_1"
    assert persona["slots"]["name"] == {"value": "Alice", "aliases": ["Bob"]}


def test_json_privacy_repository_collapses_duplicate_entity_ids_with_mixed_slot_shapes(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    repository = JsonPrivacyRepository(path=str(repo_path))
    repo_path.write_text(
        json.dumps(
            {
                "entities": [
                    {"entity_id": "dup", "name": ["Alice"]},
                    {"entity_id": "dup", "name": {"value": "Bob", "aliases": ["B"]}},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repository.merge_and_write({"entities": [{"entity_id": "other", "phone": ["111"]}]})

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    dup_persona = next(persona for persona in stored["true_personas"] if persona["persona_id"] == "dup")
    assert dup_persona["slots"]["name"] == {"value": "Alice", "aliases": ["Bob", "B"]}


def test_json_privacy_repository_preserves_legacy_entity_id_that_matches_generated_pattern(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    repository = JsonPrivacyRepository(path=str(repo_path))
    repo_path.write_text(
        json.dumps(
            {
                "entities": [
                    {"entity_id": "legacy-name-1", "name": ["Alice"]},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repository.merge_and_write({"entities": [{"entity_id": "other", "phone": ["111"]}]})

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    persona_ids = [persona["persona_id"] for persona in stored["true_personas"]]
    assert "legacy-name-1" in persona_ids


def test_json_privacy_repository_collapses_duplicate_legacy_entity_ids_before_v2_merge(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    repository = JsonPrivacyRepository(path=str(repo_path))
    repo_path.write_text(
        json.dumps(
            {
                "entities": [
                    {"entity_id": "dup", "name": ["Alice"]},
                    {"entity_id": "dup", "phone": ["111"]},
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    repository.merge_and_write({"entities": [{"entity_id": "dup", "name": ["Bob"]}]})

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    assert len(stored["true_personas"]) == 1
    persona = stored["true_personas"][0]
    assert persona["persona_id"] == "dup"
    assert persona["slots"]["name"] == {"value": "Alice", "aliases": ["Bob"]}
    assert persona["slots"]["phone"] == {"value": "111", "aliases": []}


def test_json_privacy_repository_dedupes_duplicate_flat_legacy_values_with_same_stable_id(tmp_path) -> None:
    repo_path = tmp_path / "privacy_repository.json"
    repository = JsonPrivacyRepository(path=str(repo_path))

    repository.merge_and_write({"name": ["张三", "张三"]})

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    names = [
        persona["slots"]["name"]["value"]
        for persona in stored["true_personas"]
        if "name" in persona.get("slots", {})
    ]
    assert names == ["张三"]


def test_json_privacy_repository_write_merge_and_reload_detector(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    repo_path = tmp_path / DEFAULT_PRIVACY_REPOSITORY_PATH
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    repo_path.write_text(json.dumps({"name": ["旧名"]}, ensure_ascii=False), encoding="utf-8")

    guard = PrivacyGuard(
        detector_mode="rule_based",
        decision_mode="label_only",
        detector_config={"privacy_repository_path": str(repo_path)},
    )
    guard.write_privacy_repository({"name": ["新名"]})

    stored = json.loads(repo_path.read_text(encoding="utf-8"))
    assert stored["version"] == 2
    assert [persona["slots"]["name"]["value"] for persona in stored["true_personas"]] == ["旧名", "新名"]

    assert guard.write_privacy_repository({"phone": ["13900000000"]})["status"] == "ok"
    phones = [e.value for e in guard.detector.dictionary.get(PIIAttributeType.PHONE, [])]
    assert "13900000000" in phones

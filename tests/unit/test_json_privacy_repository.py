"""JsonPrivacyRepository 合并写入测试。"""

import json

import pytest

from privacyguard import PrivacyGuard
from privacyguard.api.errors import InvalidConfigurationError
from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.json_privacy_repository import DEFAULT_PRIVACY_REPOSITORY_PATH, merge_privacy_documents


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
    assert stored["name"] == ["旧名", "新名"]

    assert guard.write_privacy_repository({"phone": ["13900000000"]})["status"] == "ok"
    phones = [e.value for e in guard.detector.dictionary.get(PIIAttributeType.PHONE, [])]
    assert "13900000000" in phones

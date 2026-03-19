"""supervised finetune 最小闭环测试。"""

import json

import pytest

torch = pytest.importorskip("torch")

from privacyguard.application.services.decision_context_builder import DecisionContextBuilder
from privacyguard.domain.enums import PIIAttributeType, PIISourceType
from privacyguard.domain.models.persona import PersonaProfile
from privacyguard.domain.models.pii import PIICandidate
from privacyguard.infrastructure.decision.de_model_engine import DEModelEngine
from privacyguard.infrastructure.mapping.in_memory_mapping_store import InMemoryMappingStore
from training.pipelines.build_dataset import build_supervised_jsonl_dataset
from training.pipelines.run_supervised_finetune import SupervisedFinetuneConfig, run_supervised_finetune


class _PersonaRepository:
    def __init__(self, personas: list[PersonaProfile]) -> None:
        self._personas = {item.persona_id: item for item in personas}

    def get_persona(self, persona_id: str) -> PersonaProfile | None:
        return self._personas.get(persona_id)

    def list_personas(self) -> list[PersonaProfile]:
        return list(self._personas.values())

    def get_slot_value(self, persona_id: str, attr_type: PIIAttributeType) -> str | None:
        persona = self.get_persona(persona_id)
        if persona is None:
            return None
        return persona.slots.get(attr_type)


def test_supervised_finetune_outputs_checkpoint_loadable_by_torch_runtime(tmp_path) -> None:
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-train",
                display_name="训练角色",
                slots={
                    PIIAttributeType.NAME: "李四",
                    PIIAttributeType.PHONE: "13900001111",
                },
                stats={"exposure_count": 0},
            )
        ]
    )
    mapping_store = InMemoryMappingStore()
    context_builder = DecisionContextBuilder(mapping_store=mapping_store, persona_repository=persona_repo)
    heuristic_engine = DEModelEngine(persona_repository=persona_repo, mapping_store=mapping_store)

    contexts = [
        context_builder.build(
            session_id="session-supervised",
            turn_id=1,
            prompt_text="请联系张三，电话 13800138000",
            candidates=[
                PIICandidate(
                    entity_id="cand-name",
                    text="张三",
                    normalized_text="张三",
                    attr_type=PIIAttributeType.NAME,
                    source=PIISourceType.PROMPT,
                    span_start=3,
                    span_end=5,
                    confidence=0.96,
                ),
                PIICandidate(
                    entity_id="cand-phone",
                    text="13800138000",
                    normalized_text="13800138000",
                    attr_type=PIIAttributeType.PHONE,
                    source=PIISourceType.PROMPT,
                    span_start=9,
                    span_end=20,
                    confidence=0.95,
                ),
            ],
        ),
        context_builder.build(
            session_id="session-supervised",
            turn_id=2,
            prompt_text="张三来自某机构",
            candidates=[
                PIICandidate(
                    entity_id="cand-name-2",
                    text="张三",
                    normalized_text="张三",
                    attr_type=PIIAttributeType.NAME,
                    source=PIISourceType.PROMPT,
                    span_start=0,
                    span_end=2,
                    confidence=0.94,
                ),
                PIICandidate(
                    entity_id="cand-org",
                    text="某机构",
                    normalized_text="某机构",
                    attr_type=PIIAttributeType.ORGANIZATION,
                    source=PIISourceType.PROMPT,
                    span_start=4,
                    span_end=7,
                    confidence=0.91,
                ),
            ],
        ),
    ]
    plans = [heuristic_engine.plan(context) for context in contexts]
    dataset_path = build_supervised_jsonl_dataset(zip(contexts, plans), tmp_path / "train.jsonl")

    payload = json.loads(dataset_path.read_text(encoding="utf-8").splitlines()[0])
    assert payload["candidate_texts"] == ["张三", "13800138000"]
    assert payload["persona_ids"] == ["persona-train"]
    assert payload["labels"]["target_persona_id"] == "persona-train"
    assert payload["labels"]["candidate_actions"]["cand-name"] == "PERSONA_SLOT"

    result = run_supervised_finetune(
        SupervisedFinetuneConfig(
            train_jsonl=dataset_path,
            output_dir=tmp_path / "artifacts",
            epochs=1,
            batch_size=2,
            learning_rate=1e-3,
            device="cpu",
            seed=7,
        )
    )

    assert result.checkpoint_path.exists()
    assert result.metrics_path.exists()

    torch_engine = DEModelEngine(
        persona_repository=persona_repo,
        mapping_store=InMemoryMappingStore(),
        runtime_type="torch",
        checkpoint_path=str(result.checkpoint_path),
    )
    torch_plan = torch_engine.plan(contexts[0])

    assert torch_plan.metadata["runtime_type"] == "torch_runtime"
    assert len(torch_plan.actions) == len(contexts[0].candidates)

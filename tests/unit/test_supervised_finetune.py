"""Minimal supervised finetune integration test."""

from contextlib import contextmanager
import json
from pathlib import Path
import shutil
from uuid import uuid4

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

    def get_slot_replacement_text(
        self,
        persona_id: str,
        attr_type: PIIAttributeType,
        source_text: str,
    ) -> str | None:
        return self.get_slot_value(persona_id, attr_type)


@contextmanager
def _workspace_temp_dir(prefix: str):
    root = Path("artifacts") / "test_tmp"
    root.mkdir(parents=True, exist_ok=True)
    directory = root / f"{prefix}-{uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def test_supervised_finetune_outputs_checkpoint_loadable_by_torch_runtime() -> None:
    persona_repo = _PersonaRepository(
        [
            PersonaProfile(
                persona_id="persona-train",
                display_name="Training Persona",
                slots={
                    PIIAttributeType.NAME: "Li Si",
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
            prompt_text="Contact Zhang San at 13800138000",
            candidates=[
                PIICandidate(
                    entity_id="cand-name",
                    text="Zhang San",
                    normalized_text="zhang san",
                    attr_type=PIIAttributeType.NAME,
                    source=PIISourceType.PROMPT,
                    span_start=8,
                    span_end=17,
                    confidence=0.96,
                ),
                PIICandidate(
                    entity_id="cand-phone",
                    text="13800138000",
                    normalized_text="13800138000",
                    attr_type=PIIAttributeType.PHONE,
                    source=PIISourceType.PROMPT,
                    span_start=21,
                    span_end=32,
                    confidence=0.95,
                ),
            ],
        ),
        context_builder.build(
            session_id="session-supervised",
            turn_id=2,
            prompt_text="Zhang San works at Example Labs",
            candidates=[
                PIICandidate(
                    entity_id="cand-name-2",
                    text="Zhang San",
                    normalized_text="zhang san",
                    attr_type=PIIAttributeType.NAME,
                    source=PIISourceType.PROMPT,
                    span_start=0,
                    span_end=9,
                    confidence=0.94,
                ),
                PIICandidate(
                    entity_id="cand-org",
                    text="Example Labs",
                    normalized_text="example labs",
                    attr_type=PIIAttributeType.ORGANIZATION,
                    source=PIISourceType.PROMPT,
                    span_start=19,
                    span_end=31,
                    confidence=0.91,
                ),
            ],
        ),
    ]

    with _workspace_temp_dir("supervised-finetune") as temp_dir:
        plans = [heuristic_engine.plan(context) for context in contexts]
        dataset_path = build_supervised_jsonl_dataset(zip(contexts, plans), temp_dir / "train.jsonl")

        payload = json.loads(dataset_path.read_text(encoding="utf-8").splitlines()[0])
        assert payload["candidate_texts"] == ["Zhang San", "13800138000"]
        assert payload["persona_ids"] == ["persona-train"]
        assert payload["labels"]["target_persona_id"] == "persona-train"
        assert payload["labels"]["candidate_actions"]["cand-name"] == "PERSONA_SLOT"

        result = run_supervised_finetune(
            SupervisedFinetuneConfig(
                train_jsonl=dataset_path,
                output_dir=temp_dir / "artifacts",
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

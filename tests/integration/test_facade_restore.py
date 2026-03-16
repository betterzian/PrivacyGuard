"""Facade restore 集成测试。"""

from privacyguard.api.dto import RestoreRequest
from privacyguard.api.facade import PrivacyGuardFacade
from privacyguard.domain.enums import ActionType, PIIAttributeType, PIISourceType
from privacyguard.domain.models.mapping import ReplacementRecord


def test_facade_restore_can_recover_text_from_mapping() -> None:
    """验证 facade.restore 可根据 mapping 恢复文本。"""
    facade = PrivacyGuardFacade.from_config_file("configs/default.yaml")
    facade.mapping_store.save_replacements(
        session_id="s-facade-restore",
        turn_id=1,
        records=[
            ReplacementRecord(
                session_id="s-facade-restore",
                turn_id=1,
                candidate_id="c1",
                source_text="张三",
                replacement_text="<NAME>",
                attr_type=PIIAttributeType.NAME,
                action_type=ActionType.GENERICIZE,
                source=PIISourceType.PROMPT,
            )
        ],
    )
    response = facade.restore(
        RestoreRequest(
            session_id="s-facade-restore",
            turn_id=1,
            cloud_text="你好 <NAME>",
        )
    )

    assert response.restored_text == "你好 张三"
    assert len(response.restored_slots) == 1


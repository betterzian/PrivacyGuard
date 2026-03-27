"""PII 检测器抽象接口。"""

from typing import Protocol

from privacyguard.domain.enums import PIIAttributeType, ProtectionLevel
from privacyguard.domain.models.ocr import OCRTextBlock
from privacyguard.domain.models.pii import PIICandidate


class PIIDetector(Protocol):
    """定义 PII 检测模块最小职责接口。"""

    def detect(
        self,
        prompt_text: str,
        ocr_blocks: list[OCRTextBlock],
        *,
        session_id: str | None = None,
        turn_id: int | None = None,
        protection_level: ProtectionLevel | str = ProtectionLevel.STRONG,
        detector_overrides: dict[PIIAttributeType | str, float] | None = None,
    ) -> list[PIICandidate]:
        """识别文本与 OCR 中的隐私候选实体。"""

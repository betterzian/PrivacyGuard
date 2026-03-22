"""GENERICIZE 替换文案的统一渲染。

与 `label_only` / `label_persona_mixed` / `de_model` 等决策模式解耦：各模式只对每个 PII
候选产出 ``KEEP`` / ``GENERICIZE`` / ``PERSONA_SLOT``；凡 ``GENERICIZE`` 的展示用占位字符串
均由本模块生成，避免在多处重复维护属性→标签映射。
"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType

# 对外只读：属性类型 → 占位符中的中文标签名（不含尖括号与序号）
GENERIC_PLACEHOLDER_LABELS: dict[PIIAttributeType, str] = {
    PIIAttributeType.NAME: "姓名",
    PIIAttributeType.LOCATION_CLUE: "位置",
    PIIAttributeType.PHONE: "手机号",
    PIIAttributeType.CARD_NUMBER: "卡号",
    PIIAttributeType.BANK_ACCOUNT: "银行账号",
    PIIAttributeType.PASSPORT_NUMBER: "护照号",
    PIIAttributeType.DRIVER_LICENSE: "驾驶证号",
    PIIAttributeType.EMAIL: "邮箱",
    PIIAttributeType.ADDRESS: "地址",
    PIIAttributeType.ID_NUMBER: "身份证号",
    PIIAttributeType.ORGANIZATION: "机构",
    PIIAttributeType.NUMERIC: "数字",
    PIIAttributeType.TEXTUAL: "文字",
    PIIAttributeType.OTHER: "敏感信息",
}


def generic_placeholder_label(attr_type: PIIAttributeType) -> str:
    """返回占位符内的中文标签片段（如 ``姓名``、``位置``），不含括号与序号。"""
    return GENERIC_PLACEHOLDER_LABELS.get(attr_type, "敏感信息")


def render_generic_replacement_text(attr_type: PIIAttributeType, index: int = 1) -> str:
    """渲染 GENERICIZE 使用的标准占位字符串，格式为 ``<姓名1>``、``<位置2>`` 等。"""
    label = generic_placeholder_label(attr_type)
    idx = max(1, index)
    return f"<{label}{idx}>"

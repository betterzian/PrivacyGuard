"""GENERICIZE 替换文案的统一渲染。

与 `label_only` / `label_persona_mixed` / `de_model` 等决策模式解耦：各模式只对每个 PII
候选产出 ``KEEP`` / ``GENERICIZE`` / ``PERSONA_SLOT``；凡 ``GENERICIZE`` 的展示用占位字符串
均由本模块生成，避免在多处重复维护属性→标签映射。
"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType

# 对外只读：属性类型 → 占位符中的中文标签名（不含尖括号）
GENERIC_PLACEHOLDER_LABELS_ZH: dict[PIIAttributeType, str] = {
    PIIAttributeType.NAME: "姓名",
    PIIAttributeType.PHONE: "手机号",
    PIIAttributeType.CARD_NUMBER: "卡号",
    PIIAttributeType.BANK_ACCOUNT: "银行账号",
    PIIAttributeType.PASSPORT_NUMBER: "护照号",
    PIIAttributeType.DRIVER_LICENSE: "驾驶证号",
    PIIAttributeType.EMAIL: "邮箱",
    PIIAttributeType.ADDRESS: "地址",
    PIIAttributeType.ID_NUMBER: "身份证号",
    PIIAttributeType.ORGANIZATION: "机构",
    PIIAttributeType.TIME: "时间",
    PIIAttributeType.NUMERIC: "数字",
    PIIAttributeType.TEXTUAL: "文字",
    PIIAttributeType.OTHER: "敏感信息",
}

GENERIC_PLACEHOLDER_LABELS_EN: dict[PIIAttributeType, str] = {
    PIIAttributeType.NAME: "name",
    PIIAttributeType.PHONE: "phone",
    PIIAttributeType.CARD_NUMBER: "card",
    PIIAttributeType.BANK_ACCOUNT: "account",
    PIIAttributeType.PASSPORT_NUMBER: "passport",
    PIIAttributeType.DRIVER_LICENSE: "license",
    PIIAttributeType.EMAIL: "email",
    PIIAttributeType.ADDRESS: "address",
    PIIAttributeType.ID_NUMBER: "id",
    PIIAttributeType.ORGANIZATION: "organization",
    PIIAttributeType.TIME: "time",
    PIIAttributeType.NUMERIC: "number",
    PIIAttributeType.TEXTUAL: "text",
    PIIAttributeType.OTHER: "sensitive",
}

# 兼容旧导入路径；默认暴露中文标签表。
GENERIC_PLACEHOLDER_LABELS = GENERIC_PLACEHOLDER_LABELS_ZH

def _contains_cjk(text: str | None) -> bool:
    return bool(text) and any("\u4e00" <= char <= "\u9fff" for char in text)


def generic_placeholder_label(attr_type: PIIAttributeType, *, source_text: str | None = None) -> str:
    """返回占位符内的标签片段（如 ``姓名``、``name``），不含括号。"""
    if _contains_cjk(source_text):
        return GENERIC_PLACEHOLDER_LABELS_ZH.get(attr_type, "敏感信息")
    return GENERIC_PLACEHOLDER_LABELS_EN.get(attr_type, "sensitive")


def render_generic_replacement_text(
    attr_type: PIIAttributeType,
    *,
    source_text: str | None = None,
    index: int | None = None,
) -> str:
    """渲染 GENERICIZE 使用的标准占位字符串，格式为 ``<姓名1>``、``<name2>`` 等。"""
    label = generic_placeholder_label(attr_type, source_text=source_text)
    if index is not None:
        label = f"{label}{index}"
    return f"<{label}>"

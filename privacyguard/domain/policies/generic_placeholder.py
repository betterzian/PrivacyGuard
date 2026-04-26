"""GENERICIZE 替换文案的统一渲染。

与 `label_only` / `label_persona_mixed` / `de_model` 等决策模式解耦：各模式只对每个 PII
候选产出 ``KEEP`` / ``GENERICIZE`` / ``PERSONA_SLOT``；凡 ``GENERICIZE`` 的展示用占位字符串
均由本模块生成，避免在多处重复维护属性→标签映射。

新格式统一为 ``[[TYPE#N]]`` / ``[[TYPE#N.SPEC]]``（见 :mod:`placeholder_labels`）；
中英标签表仅供 policy_context 等训练特征侧继续复用。
"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.domain.policies.placeholder_labels import (
    attr_type_code,
    format_placeholder,
)

# 对外只读：属性类型 → 占位符中的中文标签名（不含尖括号）
GENERIC_PLACEHOLDER_LABELS_ZH: dict[PIIAttributeType, str] = {
    PIIAttributeType.NAME: "姓名",
    PIIAttributeType.PHONE: "手机号",
    PIIAttributeType.BANK_NUMBER: "银行号",
    PIIAttributeType.PASSPORT_NUMBER: "护照号",
    PIIAttributeType.DRIVER_LICENSE: "驾驶证号",
    PIIAttributeType.LICENSE_PLATE: "车牌号",
    PIIAttributeType.EMAIL: "邮箱",
    PIIAttributeType.ADDRESS: "地址",
    PIIAttributeType.DETAILS: "地址细节",
    PIIAttributeType.ID_NUMBER: "身份证号",
    PIIAttributeType.ORGANIZATION: "机构",
    PIIAttributeType.TIME: "时间",
    PIIAttributeType.AMOUNT: "金额",
    PIIAttributeType.NUM: "数字",
    PIIAttributeType.ALNUM: "字母数字",
}

GENERIC_PLACEHOLDER_LABELS_EN: dict[PIIAttributeType, str] = {
    PIIAttributeType.NAME: "name",
    PIIAttributeType.PHONE: "phone",
    PIIAttributeType.BANK_NUMBER: "bank_number",
    PIIAttributeType.PASSPORT_NUMBER: "passport",
    PIIAttributeType.DRIVER_LICENSE: "license",
    PIIAttributeType.LICENSE_PLATE: "license_plate",
    PIIAttributeType.EMAIL: "email",
    PIIAttributeType.ADDRESS: "address",
    PIIAttributeType.DETAILS: "address_detail",
    PIIAttributeType.ID_NUMBER: "id",
    PIIAttributeType.ORGANIZATION: "organization",
    PIIAttributeType.TIME: "time",
    PIIAttributeType.AMOUNT: "amount",
    PIIAttributeType.NUM: "num",
    PIIAttributeType.ALNUM: "alnum",
}

# 兼容旧导入路径；默认暴露中文标签表。
GENERIC_PLACEHOLDER_LABELS = GENERIC_PLACEHOLDER_LABELS_ZH


def _contains_cjk(text: str | None) -> bool:
    return bool(text) and any("\u4e00" <= char <= "\u9fff" for char in text)


def generic_placeholder_label(attr_type: PIIAttributeType, *, source_text: str | None = None) -> str:
    """返回用于 policy_context 训练特征的中/英文标签（不含括号）。

    与占位符渲染无关；渲染路径统一走 :func:`render_placeholder`。
    """
    if _contains_cjk(source_text):
        return GENERIC_PLACEHOLDER_LABELS_ZH.get(attr_type, "敏感信息")
    return GENERIC_PLACEHOLDER_LABELS_EN.get(attr_type, "sensitive")


def render_placeholder(
    attr_type: PIIAttributeType,
    *,
    index: int,
    address_spec: str | None = None,
    fragment_type: str | None = None,
    fragment_length: int | None = None,
) -> str:
    """按统一格式渲染 GENERICIZE 占位符字符串。

    - ``attr_type = ADDRESS`` + ``address_spec`` → ``[[ADDR#N.CITY-DIST-ROAD]]``；spec 空时退化为 ``[[ADDR#N]]``。
    - ``fragment_type`` + ``fragment_length``（NUM / ALNUM）→ ``[[NUM#N.LEN=L]]``。
    - 其它：``[[TYPE#N]]``。
    """
    if fragment_type is not None and fragment_length is not None:
        frag_type = str(fragment_type or "").strip().upper()
        if frag_type not in {"NUM", "ALNUM"}:
            raise ValueError(f"fragment_type 仅支持 NUM/ALNUM，收到: {fragment_type!r}")
        if fragment_length <= 0:
            raise ValueError("fragment_length 必须 > 0")
        return format_placeholder(frag_type, index, f"LEN={fragment_length}")

    label = attr_type_code(attr_type)
    if not label:
        raise ValueError(f"未登记占位符短码的 attr_type: {attr_type!r}")

    if attr_type == PIIAttributeType.ADDRESS:
        spec = str(address_spec or "").strip()
        return format_placeholder(label, index, spec)
    return format_placeholder(label, index, "")


__all__ = [
    "GENERIC_PLACEHOLDER_LABELS",
    "GENERIC_PLACEHOLDER_LABELS_EN",
    "GENERIC_PLACEHOLDER_LABELS_ZH",
    "generic_placeholder_label",
    "render_placeholder",
]

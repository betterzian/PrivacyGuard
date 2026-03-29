"""新 detector 的字段标签定义。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import LabelSpec, NameComponentHint

_LABEL_SPECS: tuple[LabelSpec, ...] = (
    LabelSpec("邮箱地址", PIIAttributeType.EMAIL, 300, "context_email_field", "ocr_label_email_field"),
    LabelSpec("email address", PIIAttributeType.EMAIL, 299, "context_email_field", "ocr_label_email_field", ascii_boundary=True),
    LabelSpec("e-mail", PIIAttributeType.EMAIL, 298, "context_email_field", "ocr_label_email_field", ascii_boundary=True),
    LabelSpec("email", PIIAttributeType.EMAIL, 297, "context_email_field", "ocr_label_email_field", ascii_boundary=True),
    LabelSpec("手机号码", PIIAttributeType.PHONE, 290, "context_phone_field", "ocr_label_phone_field"),
    LabelSpec("手机号", PIIAttributeType.PHONE, 289, "context_phone_field", "ocr_label_phone_field"),
    LabelSpec("phone number", PIIAttributeType.PHONE, 288, "context_phone_field", "ocr_label_phone_field", ascii_boundary=True),
    LabelSpec("mobile", PIIAttributeType.PHONE, 287, "context_phone_field", "ocr_label_phone_field", ascii_boundary=True),
    LabelSpec("phone", PIIAttributeType.PHONE, 286, "context_phone_field", "ocr_label_phone_field", ascii_boundary=True),
    LabelSpec("身份证号", PIIAttributeType.ID_NUMBER, 280, "context_id_field", "ocr_label_id_field"),
    LabelSpec("身份证号码", PIIAttributeType.ID_NUMBER, 279, "context_id_field", "ocr_label_id_field"),
    LabelSpec("id number", PIIAttributeType.ID_NUMBER, 278, "context_id_field", "ocr_label_id_field", ascii_boundary=True),
    LabelSpec("passport", PIIAttributeType.PASSPORT_NUMBER, 277, "context_passport_field", "ocr_label_passport_field", ascii_boundary=True),
    LabelSpec("driver license", PIIAttributeType.DRIVER_LICENSE, 276, "context_driver_license_field", "ocr_label_driver_license_field", ascii_boundary=True),
    LabelSpec("公司名称", PIIAttributeType.ORGANIZATION, 260, "context_organization_field", "ocr_label_organization_field"),
    LabelSpec("单位名称", PIIAttributeType.ORGANIZATION, 259, "context_organization_field", "ocr_label_organization_field"),
    LabelSpec("organization", PIIAttributeType.ORGANIZATION, 258, "context_organization_field", "ocr_label_organization_field", ascii_boundary=True),
    LabelSpec("company name", PIIAttributeType.ORGANIZATION, 257, "context_organization_field", "ocr_label_organization_field", ascii_boundary=True),
    LabelSpec("company", PIIAttributeType.ORGANIZATION, 256, "context_organization_field", "ocr_label_organization_field", ascii_boundary=True),
    LabelSpec("家庭住址", PIIAttributeType.ADDRESS, 250, "context_address_field", "ocr_label_address_field"),
    LabelSpec("联系地址", PIIAttributeType.ADDRESS, 249, "context_address_field", "ocr_label_address_field"),
    LabelSpec("住址", PIIAttributeType.ADDRESS, 248, "context_address_field", "ocr_label_address_field"),
    LabelSpec("地址", PIIAttributeType.ADDRESS, 247, "context_address_field", "ocr_label_address_field"),
    LabelSpec("address line", PIIAttributeType.ADDRESS, 246, "context_address_field", "ocr_label_address_field", ascii_boundary=True),
    LabelSpec("address", PIIAttributeType.ADDRESS, 245, "context_address_field", "ocr_label_address_field", ascii_boundary=True),
    LabelSpec("住客姓名", PIIAttributeType.NAME, 230, "context_name_field", "ocr_label_name_field", NameComponentHint.FULL),
    LabelSpec("姓名", PIIAttributeType.NAME, 229, "context_name_field", "ocr_label_name_field", NameComponentHint.FULL),
    LabelSpec("full name", PIIAttributeType.NAME, 228, "context_name_field", "ocr_label_name_field", NameComponentHint.FULL, True),
    LabelSpec("name", PIIAttributeType.NAME, 227, "context_name_field", "ocr_label_name_field", NameComponentHint.FULL, True),
    LabelSpec("surname", PIIAttributeType.NAME, 226, "context_name_family_field", "ocr_label_name_family_field", NameComponentHint.FAMILY, True),
    LabelSpec("family name", PIIAttributeType.NAME, 225, "context_name_family_field", "ocr_label_name_family_field", NameComponentHint.FAMILY, True),
    LabelSpec("last name", PIIAttributeType.NAME, 224, "context_name_family_field", "ocr_label_name_family_field", NameComponentHint.FAMILY, True),
    LabelSpec("姓", PIIAttributeType.NAME, 223, "context_name_family_field", "ocr_label_name_family_field", NameComponentHint.FAMILY),
    LabelSpec("given name", PIIAttributeType.NAME, 222, "context_name_given_field", "ocr_label_name_given_field", NameComponentHint.GIVEN, True),
    LabelSpec("first name", PIIAttributeType.NAME, 221, "context_name_given_field", "ocr_label_name_given_field", NameComponentHint.GIVEN, True),
    LabelSpec("名", PIIAttributeType.NAME, 220, "context_name_given_field", "ocr_label_name_given_field", NameComponentHint.GIVEN),
    LabelSpec("middle name", PIIAttributeType.NAME, 219, "context_name_middle_field", "ocr_label_name_middle_field", NameComponentHint.MIDDLE, True),
)

__all__ = ["_LABEL_SPECS"]

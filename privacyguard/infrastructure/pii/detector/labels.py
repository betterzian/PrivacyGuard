"""新 detector 的字段标签定义。"""

from __future__ import annotations

from privacyguard.domain.enums import PIIAttributeType
from privacyguard.infrastructure.pii.detector.models import LabelSpec

_LABEL_SPECS: tuple[LabelSpec, ...] = (
    LabelSpec("邮箱地址", PIIAttributeType.EMAIL, 300, "context_email_field", "ocr_label_email_field", "structured"),
    LabelSpec("email address", PIIAttributeType.EMAIL, 299, "context_email_field", "ocr_label_email_field", "structured", ascii_boundary=True),
    LabelSpec("e-mail", PIIAttributeType.EMAIL, 298, "context_email_field", "ocr_label_email_field", "structured", ascii_boundary=True),
    LabelSpec("email", PIIAttributeType.EMAIL, 297, "context_email_field", "ocr_label_email_field", "structured", ascii_boundary=True),
    LabelSpec("手机号码", PIIAttributeType.PHONE, 290, "context_phone_field", "ocr_label_phone_field", "structured"),
    LabelSpec("手机号", PIIAttributeType.PHONE, 289, "context_phone_field", "ocr_label_phone_field", "structured"),
    LabelSpec("phone number", PIIAttributeType.PHONE, 288, "context_phone_field", "ocr_label_phone_field", "structured", ascii_boundary=True),
    LabelSpec("mobile", PIIAttributeType.PHONE, 287, "context_phone_field", "ocr_label_phone_field", "structured", ascii_boundary=True),
    LabelSpec("phone", PIIAttributeType.PHONE, 286, "context_phone_field", "ocr_label_phone_field", "structured", ascii_boundary=True),
    LabelSpec("身份证号", PIIAttributeType.ID_NUMBER, 280, "context_id_field", "ocr_label_id_field", "structured"),
    LabelSpec("身份证号码", PIIAttributeType.ID_NUMBER, 279, "context_id_field", "ocr_label_id_field", "structured"),
    LabelSpec("id number", PIIAttributeType.ID_NUMBER, 278, "context_id_field", "ocr_label_id_field", "structured", ascii_boundary=True),
    LabelSpec("passport", PIIAttributeType.PASSPORT_NUMBER, 277, "context_passport_field", "ocr_label_passport_field", "structured", ascii_boundary=True),
    LabelSpec("driver license", PIIAttributeType.DRIVER_LICENSE, 276, "context_driver_license_field", "ocr_label_driver_license_field", "structured", ascii_boundary=True),
    LabelSpec("公司名称", PIIAttributeType.ORGANIZATION, 260, "context_organization_field", "ocr_label_organization_field", "organization"),
    LabelSpec("单位名称", PIIAttributeType.ORGANIZATION, 259, "context_organization_field", "ocr_label_organization_field", "organization"),
    LabelSpec("organization", PIIAttributeType.ORGANIZATION, 258, "context_organization_field", "ocr_label_organization_field", "organization", ascii_boundary=True),
    LabelSpec("company name", PIIAttributeType.ORGANIZATION, 257, "context_organization_field", "ocr_label_organization_field", "organization", ascii_boundary=True),
    LabelSpec("company", PIIAttributeType.ORGANIZATION, 256, "context_organization_field", "ocr_label_organization_field", "organization", ascii_boundary=True),
    LabelSpec("家庭住址", PIIAttributeType.ADDRESS, 250, "context_address_field", "ocr_label_address_field", "address"),
    LabelSpec("联系地址", PIIAttributeType.ADDRESS, 249, "context_address_field", "ocr_label_address_field", "address"),
    LabelSpec("住址", PIIAttributeType.ADDRESS, 248, "context_address_field", "ocr_label_address_field", "address"),
    LabelSpec("地址", PIIAttributeType.ADDRESS, 247, "context_address_field", "ocr_label_address_field", "address"),
    LabelSpec("address line", PIIAttributeType.ADDRESS, 246, "context_address_field", "ocr_label_address_field", "address", ascii_boundary=True),
    LabelSpec("address", PIIAttributeType.ADDRESS, 245, "context_address_field", "ocr_label_address_field", "address", ascii_boundary=True),
    LabelSpec("住客姓名", PIIAttributeType.NAME, 230, "context_name_field", "ocr_label_name_field", "name", "full"),
    LabelSpec("姓名", PIIAttributeType.NAME, 229, "context_name_field", "ocr_label_name_field", "name", "full"),
    LabelSpec("full name", PIIAttributeType.NAME, 228, "context_name_field", "ocr_label_name_field", "name", "full", True),
    LabelSpec("name", PIIAttributeType.NAME, 227, "context_name_field", "ocr_label_name_field", "name", "full", True),
    LabelSpec("surname", PIIAttributeType.NAME, 226, "context_name_family_field", "ocr_label_name_family_field", "name", "family", True),
    LabelSpec("family name", PIIAttributeType.NAME, 225, "context_name_family_field", "ocr_label_name_family_field", "name", "family", True),
    LabelSpec("last name", PIIAttributeType.NAME, 224, "context_name_family_field", "ocr_label_name_family_field", "name", "family", True),
    LabelSpec("姓", PIIAttributeType.NAME, 223, "context_name_family_field", "ocr_label_name_family_field", "name", "family"),
    LabelSpec("given name", PIIAttributeType.NAME, 222, "context_name_given_field", "ocr_label_name_given_field", "name", "given", True),
    LabelSpec("first name", PIIAttributeType.NAME, 221, "context_name_given_field", "ocr_label_name_given_field", "name", "given", True),
    LabelSpec("名", PIIAttributeType.NAME, 220, "context_name_given_field", "ocr_label_name_given_field", "name", "given"),
    LabelSpec("middle name", PIIAttributeType.NAME, 219, "context_name_middle_field", "ocr_label_name_middle_field", "name", "middle", True),
)

__all__ = ["_LABEL_SPECS"]

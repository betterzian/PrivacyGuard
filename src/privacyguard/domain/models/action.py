"""还原阶段动作模型定义。"""

from pydantic import BaseModel


class RestoredSlot(BaseModel):
    """表示还原后命中的槽位结果。"""

    attr_type: str
    value: str
    source_placeholder: str | None = None


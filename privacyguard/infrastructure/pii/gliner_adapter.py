"""GLiNER 轻量 NER 适配层。"""

from dataclasses import dataclass


@dataclass
class NERSpan:
    """表示 NER 输出的一个文本片段。"""

    text: str
    label: str
    score: float


class GLiNERAdapter:
    """封装 GLiNER 依赖加载与推理入口。"""

    def __init__(self, model_name: str = "urchade/gliner_small-v2.1", enabled: bool = True) -> None:
        """初始化适配器并尝试加载外部依赖。"""
        self.model_name = model_name
        self.enabled = enabled
        self.available = False
        self._model = None
        self._load_model()

    def _load_model(self) -> None:
        """尝试加载 GLiNER 模型，失败时保持不可用状态。"""
        if not self.enabled:
            return
        try:
            from gliner import GLiNER
        except Exception:
            self.available = False
            self._model = None
            return
        try:
            self._model = GLiNER.from_pretrained(self.model_name)
            self.available = True
        except Exception:
            self.available = False
            self._model = None

    def predict(self, text: str, labels: list[str] | None = None) -> list[NERSpan]:
        """执行 NER 推理并返回统一结构。"""
        if not self.available or self._model is None:
            return []
        target_labels = labels or ["person", "phone", "email", "address", "id"]
        try:
            raw_items = self._model.predict_entities(text, target_labels)
        except Exception:
            return []
        spans: list[NERSpan] = []
        for item in raw_items:
            spans.append(
                NERSpan(
                    text=str(item.get("text", "")),
                    label=str(item.get("label", "")),
                    score=float(item.get("score", 0.0)),
                )
            )
        return spans


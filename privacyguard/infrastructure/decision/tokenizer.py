"""de_model 训练/导出使用的轻量字符 tokenizer。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class EncodedText:
    """表示定长编码后的文本序列。"""

    input_ids: list[int]
    attention_mask: list[int]


class CharacterHashTokenizer:
    """使用稳定字符哈希的极简 tokenizer。"""

    def __init__(
        self,
        *,
        vocab_size: int = 2048,
        pad_token_id: int = 0,
        unk_token_id: int = 1,
    ) -> None:
        if vocab_size < 8:
            raise ValueError("vocab_size 必须至少为 8。")
        self.vocab_size = vocab_size
        self.pad_token_id = pad_token_id
        self.unk_token_id = unk_token_id

    def encode(self, text: str, *, max_length: int) -> EncodedText:
        """将任意文本编码为固定长度 token 序列。"""
        if max_length <= 0:
            raise ValueError("max_length 必须大于 0。")
        normalized = self._normalize(text)
        token_ids = [self._token_for_char(char) for char in normalized[:max_length]]
        attention_mask = [1] * len(token_ids)
        padding = max_length - len(token_ids)
        if padding > 0:
            token_ids.extend([self.pad_token_id] * padding)
            attention_mask.extend([0] * padding)
        return EncodedText(input_ids=token_ids, attention_mask=attention_mask)

    def _normalize(self, text: str | None) -> str:
        if not text:
            return ""
        return str(text).strip()

    def _token_for_char(self, char: str) -> int:
        payload = char.encode("utf-8", errors="ignore")
        if not payload:
            return self.unk_token_id
        value = 17
        modulus = max(1, self.vocab_size - 2)
        for item in payload:
            value = (value * 131 + int(item)) % modulus
        return 2 + value

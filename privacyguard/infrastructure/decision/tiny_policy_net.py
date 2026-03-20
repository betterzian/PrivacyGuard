"""de_model 的 PyTorch 原型网络。"""

from __future__ import annotations

from dataclasses import dataclass, replace

import torch
from torch import nn
from torch.nn import functional as F

from privacyguard.domain.enums import ActionType
from privacyguard.infrastructure.decision.features import (
    CANDIDATE_FEATURE_DIM,
    PAGE_FEATURE_DIM,
    PERSONA_FEATURE_DIM,
)

ACTION_ORDER: tuple[ActionType, ActionType, ActionType] = (
    ActionType.KEEP,
    ActionType.GENERICIZE,
    ActionType.PERSONA_SLOT,
)
PROTECT_ORDER: tuple[str, str] = ("KEEP", "REWRITE")
REWRITE_MODE_ORDER: tuple[str, str] = (
    ActionType.GENERICIZE.value,
    ActionType.PERSONA_SLOT.value,
)


@dataclass(slots=True)
class TinyPolicyNetConfig:
    """TinyPolicyNet 的结构配置。"""

    vocab_size: int = 2048
    max_text_length: int = 48
    page_feature_dim: int = PAGE_FEATURE_DIM
    candidate_feature_dim: int = CANDIDATE_FEATURE_DIM
    persona_feature_dim: int = PERSONA_FEATURE_DIM
    char_embedding_dim: int = 64
    text_hidden_dim: int = 96
    text_encoder_layers: int = 3
    struct_hidden_dim: int = 64
    d_model: int = 128
    transformer_layers: int = 2
    num_heads: int = 4
    ff_dim: int = 256
    dropout: float = 0.1
    action_size: int = 3
    protect_size: int = len(PROTECT_ORDER)
    rewrite_mode_size: int = len(REWRITE_MODE_ORDER)


@dataclass(slots=True)
class TinyPolicyBatch:
    """TinyPolicyNet 前向所需的定长 batch。"""

    page_features: torch.Tensor
    candidate_features: torch.Tensor
    candidate_mask: torch.Tensor
    candidate_text_ids: torch.Tensor
    candidate_text_mask: torch.Tensor
    candidate_prompt_ids: torch.Tensor
    candidate_prompt_mask: torch.Tensor
    candidate_ocr_ids: torch.Tensor
    candidate_ocr_mask: torch.Tensor
    persona_features: torch.Tensor
    persona_mask: torch.Tensor
    persona_text_ids: torch.Tensor
    persona_text_mask: torch.Tensor
    candidate_ids: list[list[str]]
    persona_ids: list[list[str]]

    def to(self, device: torch.device | str) -> "TinyPolicyBatch":
        """将 batch 张量迁移到指定 device。"""
        return replace(
            self,
            page_features=self.page_features.to(device),
            candidate_features=self.candidate_features.to(device),
            candidate_mask=self.candidate_mask.to(device),
            candidate_text_ids=self.candidate_text_ids.to(device),
            candidate_text_mask=self.candidate_text_mask.to(device),
            candidate_prompt_ids=self.candidate_prompt_ids.to(device),
            candidate_prompt_mask=self.candidate_prompt_mask.to(device),
            candidate_ocr_ids=self.candidate_ocr_ids.to(device),
            candidate_ocr_mask=self.candidate_ocr_mask.to(device),
            persona_features=self.persona_features.to(device),
            persona_mask=self.persona_mask.to(device),
            persona_text_ids=self.persona_text_ids.to(device),
            persona_text_mask=self.persona_text_mask.to(device),
        )


@dataclass(slots=True)
class TinyPolicyOutput:
    """TinyPolicyNet 的前向输出。"""

    persona_logits: torch.Tensor
    action_logits: torch.Tensor
    confidence_scores: torch.Tensor
    utility_scores: torch.Tensor
    page_summary: torch.Tensor
    persona_context: torch.Tensor
    protect_logits: torch.Tensor | None = None
    rewrite_mode_logits: torch.Tensor | None = None


class DepthwiseSeparableConvBlock(nn.Module):
    """导出友好的深度可分离一维卷积块。"""

    def __init__(self, channels: int, *, dropout: float) -> None:
        super().__init__()
        self.depthwise = nn.Conv1d(
            channels,
            channels,
            kernel_size=3,
            padding=1,
            groups=channels,
            bias=False,
        )
        self.pointwise = nn.Conv1d(channels, channels, kernel_size=1, bias=False)
        self.norm = nn.GroupNorm(1, channels)
        self.activation = nn.SiLU()
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        x = self.depthwise(x)
        x = self.pointwise(x)
        x = self.norm(x)
        x = self.activation(x)
        x = self.dropout(x)
        return x + residual


class SharedTextEncoder(nn.Module):
    """共享字符级文本编码器。"""

    def __init__(self, config: TinyPolicyNetConfig) -> None:
        super().__init__()
        self.embedding = nn.Embedding(config.vocab_size, config.char_embedding_dim, padding_idx=0)
        self.input_projection = nn.Conv1d(config.char_embedding_dim, config.text_hidden_dim, kernel_size=1)
        self.blocks = nn.ModuleList(
            [DepthwiseSeparableConvBlock(config.text_hidden_dim, dropout=config.dropout) for _ in range(config.text_encoder_layers)]
        )
        self.output_norm = nn.LayerNorm(config.text_hidden_dim)

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        x = self.embedding(input_ids)
        x = x.transpose(1, 2)
        x = self.input_projection(x)
        for block in self.blocks:
            x = block(x)
        x = x.transpose(1, 2)
        x = self.output_norm(x)
        mask = attention_mask.unsqueeze(-1).to(dtype=x.dtype)
        summed = (x * mask).sum(dim=1)
        denom = mask.sum(dim=1).clamp(min=1.0)
        return summed / denom


class TinyPolicyNet(nn.Module):
    """用于 de_model 训练/导出的轻量策略原型。"""

    def __init__(self, config: TinyPolicyNetConfig | None = None) -> None:
        super().__init__()
        self.config = config or TinyPolicyNetConfig()
        self.text_encoder = SharedTextEncoder(self.config)

        self.candidate_text_projection = nn.Sequential(
            nn.Linear(self.config.text_hidden_dim * 3, self.config.d_model),
            nn.LayerNorm(self.config.d_model),
            nn.SiLU(),
            nn.Dropout(self.config.dropout),
        )
        self.persona_text_projection = nn.Sequential(
            nn.Linear(self.config.text_hidden_dim, self.config.d_model),
            nn.LayerNorm(self.config.d_model),
            nn.SiLU(),
            nn.Dropout(self.config.dropout),
        )
        self.candidate_struct_projection = nn.Sequential(
            nn.Linear(self.config.candidate_feature_dim, self.config.struct_hidden_dim),
            nn.LayerNorm(self.config.struct_hidden_dim),
            nn.SiLU(),
            nn.Linear(self.config.struct_hidden_dim, self.config.struct_hidden_dim),
        )
        self.persona_struct_projection = nn.Sequential(
            nn.Linear(self.config.persona_feature_dim, self.config.struct_hidden_dim),
            nn.LayerNorm(self.config.struct_hidden_dim),
            nn.SiLU(),
            nn.Linear(self.config.struct_hidden_dim, self.config.struct_hidden_dim),
        )
        self.page_projection = nn.Sequential(
            nn.Linear(self.config.page_feature_dim, self.config.d_model),
            nn.LayerNorm(self.config.d_model),
            nn.SiLU(),
        )
        self.candidate_projection = nn.Sequential(
            nn.Linear(self.config.d_model + self.config.struct_hidden_dim, self.config.d_model),
            nn.LayerNorm(self.config.d_model),
            nn.SiLU(),
        )
        self.persona_projection = nn.Sequential(
            nn.Linear(self.config.d_model + self.config.struct_hidden_dim, self.config.d_model),
            nn.LayerNorm(self.config.d_model),
            nn.SiLU(),
        )

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=self.config.d_model,
            nhead=self.config.num_heads,
            dim_feedforward=self.config.ff_dim,
            dropout=self.config.dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.page_encoder = nn.TransformerEncoder(encoder_layer, num_layers=self.config.transformer_layers)
        self.page_token = nn.Parameter(torch.zeros(1, 1, self.config.d_model))

        # persona_selector 继续承担 persona_head 角色：输出 persona_id logits。
        self.persona_selector = nn.Sequential(
            nn.Linear(self.config.d_model * 3, self.config.d_model),
            nn.GELU(),
            nn.Dropout(self.config.dropout),
            nn.Linear(self.config.d_model, 1),
        )
        # 旧平面 action head 保留为过渡用途，供当前 runtime / 监督训练继续消费。
        self.action_head = nn.Sequential(
            nn.Linear(self.config.d_model * 3, self.config.d_model * 2),
            nn.GELU(),
            nn.Dropout(self.config.dropout),
            nn.Linear(self.config.d_model * 2, self.config.action_size),
        )
        # 新层级输出头：逐步收敛到 protect_decision + rewrite_mode 任务。
        self.protect_head = nn.Sequential(
            nn.Linear(self.config.d_model * 3, self.config.d_model),
            nn.GELU(),
            nn.Dropout(self.config.dropout),
            nn.Linear(self.config.d_model, self.config.protect_size),
        )
        self.rewrite_mode_head = nn.Sequential(
            nn.Linear(self.config.d_model * 3, self.config.d_model),
            nn.GELU(),
            nn.Dropout(self.config.dropout),
            nn.Linear(self.config.d_model, self.config.rewrite_mode_size),
        )
        self.confidence_head = nn.Sequential(
            nn.Linear(self.config.d_model * 3, self.config.d_model),
            nn.GELU(),
            nn.Linear(self.config.d_model, 1),
        )
        self.utility_head = nn.Sequential(
            nn.Linear(self.config.d_model * 3, self.config.d_model),
            nn.GELU(),
            nn.Linear(self.config.d_model, 1),
        )

    def forward(self, batch: TinyPolicyBatch) -> TinyPolicyOutput:
        page_hidden = self.page_projection(batch.page_features)

        # 文本编码保持轻量共享主干，继续作为辅助通道，不引入更重 tokenizer 方案。
        candidate_text = self._encode_candidate_texts(batch)
        candidate_struct = self.candidate_struct_projection(batch.candidate_features)
        candidate_tokens = self.candidate_projection(torch.cat([candidate_text, candidate_struct], dim=-1))

        persona_text = self._encode_persona_texts(batch)
        persona_struct = self.persona_struct_projection(batch.persona_features)
        persona_hidden = self.persona_projection(torch.cat([persona_text, persona_struct], dim=-1))

        page_token = self.page_token + page_hidden.unsqueeze(1)
        page_inputs = torch.cat([page_token, candidate_tokens], dim=1)
        candidate_padding_mask = torch.cat(
            [
                torch.zeros(
                    batch.candidate_mask.shape[0],
                    1,
                    dtype=torch.bool,
                    device=batch.candidate_mask.device,
                ),
                ~batch.candidate_mask,
            ],
            dim=1,
        )
        page_encoded = self.page_encoder(page_inputs, src_key_padding_mask=candidate_padding_mask)
        page_summary = page_encoded[:, 0, :]
        candidate_hidden = page_encoded[:, 1:, :]

        persona_logits = self._persona_logits(page_summary=page_summary, page_hidden=page_hidden, persona_hidden=persona_hidden, persona_mask=batch.persona_mask)
        persona_weights = self._masked_softmax(persona_logits, batch.persona_mask)
        persona_context = torch.bmm(persona_weights.unsqueeze(1), persona_hidden).squeeze(1)

        candidate_context = torch.cat(
            [
                candidate_hidden,
                page_summary.unsqueeze(1).expand_as(candidate_hidden),
                persona_context.unsqueeze(1).expand_as(candidate_hidden),
            ],
            dim=-1,
        )

        action_logits = self.action_head(candidate_context)
        protect_logits = self.protect_head(candidate_context)
        rewrite_mode_logits = self.rewrite_mode_head(candidate_context)
        confidence_scores = torch.sigmoid(self.confidence_head(candidate_context)).squeeze(-1)
        utility_scores = self.utility_head(candidate_context).squeeze(-1)

        action_logits = action_logits.masked_fill(~batch.candidate_mask.unsqueeze(-1), 0.0)
        protect_logits = protect_logits.masked_fill(~batch.candidate_mask.unsqueeze(-1), 0.0)
        rewrite_mode_logits = rewrite_mode_logits.masked_fill(~batch.candidate_mask.unsqueeze(-1), 0.0)
        confidence_scores = confidence_scores * batch.candidate_mask.to(dtype=confidence_scores.dtype)
        utility_scores = utility_scores * batch.candidate_mask.to(dtype=utility_scores.dtype)

        return TinyPolicyOutput(
            persona_logits=persona_logits,
            action_logits=action_logits,
            confidence_scores=confidence_scores,
            utility_scores=utility_scores,
            page_summary=page_summary,
            persona_context=persona_context,
            protect_logits=protect_logits,
            rewrite_mode_logits=rewrite_mode_logits,
        )

    def parameter_count(self) -> int:
        """返回可训练参数总量。"""
        return sum(parameter.numel() for parameter in self.parameters() if parameter.requires_grad)

    def load_state_dict(self, state_dict, strict: bool = True, assign: bool = False):
        """兼容旧 checkpoint。

        旧 checkpoint 只有 `action_head`，缺少新增的 `protect_head` / `rewrite_mode_head`
        时，仍允许按严格模式入口加载；新 head 将保持随机初始化。
        """

        def _super_load(strict_value: bool):
            try:
                return nn.Module.load_state_dict(self, state_dict, strict=strict_value, assign=assign)
            except TypeError:
                return nn.Module.load_state_dict(self, state_dict, strict=strict_value)

        if not strict:
            return _super_load(False)

        incompatible = _super_load(False)
        missing_keys = [
            key
            for key in incompatible.missing_keys
            if not key.startswith(("protect_head.", "rewrite_mode_head."))
        ]
        unexpected_keys = list(incompatible.unexpected_keys)
        if missing_keys or unexpected_keys:
            raise RuntimeError(
                "Error(s) in loading state_dict for TinyPolicyNet: "
                f"missing_keys={missing_keys}, unexpected_keys={unexpected_keys}"
            )
        return incompatible

    def _encode_candidate_texts(self, batch: TinyPolicyBatch) -> torch.Tensor:
        text_repr = self._encode_text_tensor(batch.candidate_text_ids, batch.candidate_text_mask)
        prompt_repr = self._encode_text_tensor(batch.candidate_prompt_ids, batch.candidate_prompt_mask)
        ocr_repr = self._encode_text_tensor(batch.candidate_ocr_ids, batch.candidate_ocr_mask)
        return self.candidate_text_projection(torch.cat([text_repr, prompt_repr, ocr_repr], dim=-1))

    def _encode_persona_texts(self, batch: TinyPolicyBatch) -> torch.Tensor:
        return self.persona_text_projection(self._encode_text_tensor(batch.persona_text_ids, batch.persona_text_mask))

    def _encode_text_tensor(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        batch_shape = input_ids.shape[:-1]
        flat_ids = input_ids.reshape(-1, input_ids.shape[-1])
        flat_mask = attention_mask.reshape(-1, attention_mask.shape[-1])
        flat_encoded = self.text_encoder(flat_ids, flat_mask)
        return flat_encoded.reshape(*batch_shape, flat_encoded.shape[-1])

    def _persona_logits(
        self,
        *,
        page_summary: torch.Tensor,
        page_hidden: torch.Tensor,
        persona_hidden: torch.Tensor,
        persona_mask: torch.Tensor,
    ) -> torch.Tensor:
        page_summary_expanded = page_summary.unsqueeze(1).expand(-1, persona_hidden.shape[1], -1)
        page_hidden_expanded = page_hidden.unsqueeze(1).expand(-1, persona_hidden.shape[1], -1)
        selector_input = torch.cat([page_summary_expanded, page_hidden_expanded, persona_hidden], dim=-1)
        logits = self.persona_selector(selector_input).squeeze(-1)
        return logits.masked_fill(~persona_mask, -1e4)

    def _masked_softmax(self, logits: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        masked_logits = logits.masked_fill(~mask, -1e4)
        weights = F.softmax(masked_logits, dim=-1)
        weights = torch.where(mask, weights, torch.zeros_like(weights))
        norm = weights.sum(dim=-1, keepdim=True).clamp(min=1e-6)
        return weights / norm

"""中文姓名规则与提交评分。"""

from __future__ import annotations

from dataclasses import dataclass

from privacyguard.domain.enums import ProtectionLevel
from privacyguard.infrastructure.pii.detector.models import Clue, ClueRole

_CJK_NAME_JOINERS = frozenset({"·", "•", "・"})
_SEED_CONTEXT_ROLES = frozenset({ClueRole.LABEL, ClueRole.START})


def _is_cjk(char: str) -> bool:
    return "\u4e00" <= char <= "\u9fff"


def compact_zh_name_text(text: str) -> str:
    """压紧中文姓名候选，只保留 CJK 与常见中点连接符。"""
    compact = []
    for char in str(text or ""):
        if char.isspace():
            continue
        if _is_cjk(char) or char in _CJK_NAME_JOINERS:
            compact.append(char)
    return "".join(compact)


@dataclass(frozen=True, slots=True)
class ZhNameScoreWeights:
    """中文姓名打分项。"""

    compound_exact_match: int
    single_strong: int
    single_medium: int
    single_weak: int
    boostable_medium_after_blacklist_pass: int
    position_first_char_of_2_to_3_char_cjk_span: int
    common_given_name_char_after_surname: int
    name_field_or_contact_context: int
    fixed_phrase_blacklist_hit: int
    non_name_field_context: int


@dataclass(frozen=True, slots=True)
class ZhNameSubmitThresholds:
    """各保护级别的中文姓名提交阈值。"""

    strong: int
    balanced: int
    weak: int

    def for_level(self, level: ProtectionLevel) -> int:
        if level == ProtectionLevel.STRONG:
            return self.strong
        if level == ProtectionLevel.BALANCED:
            return self.balanced
        return self.weak


@dataclass(frozen=True, slots=True)
class ZhSurnameMatch:
    """候选前缀的姓氏锚点。"""

    text: str
    match_kind: str
    tier: str
    base_score: int
    from_dictionary: bool = False


@dataclass(frozen=True, slots=True)
class ZhNameScoreDecision:
    """中文姓名提交决策。"""

    should_commit: bool
    total_score: int
    threshold: int
    matched_surname: str = ""
    surname_match_kind: str = "none"
    surname_tier: str = "none"
    surname_score: int = 0
    seed_context_score: int = 0
    shape_score: int = 0
    given_name_evidence_score: int = 0
    fixed_phrase_penalty: int = 0
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ZhNameRules:
    """中文姓名统一规则。"""

    compound_surnames: tuple[str, ...]
    single_surname_tiers: dict[str, frozenset[str]]
    surname_tier_by_char: dict[str, str]
    boostable_medium_surnames: frozenset[str]
    boost_blacklist_phrases: dict[str, tuple[str, ...]]
    zh_given_names: tuple[str, ...]
    given_name_tail_chars: frozenset[str]
    scoring: ZhNameScoreWeights
    submit_thresholds: ZhNameSubmitThresholds

    @property
    def single_surnames(self) -> frozenset[str]:
        return frozenset(self.surname_tier_by_char.keys())

    @property
    def all_surnames(self) -> frozenset[str]:
        return frozenset((*self.compound_surnames, *self.single_surnames))


def build_zh_name_rules(payload: object) -> ZhNameRules:
    """从 JSON 载荷构造不可变中文姓名规则对象。"""
    if not isinstance(payload, dict):
        raise ValueError("zh_name_rules.json 格式错误：根节点应为对象。")

    compound_raw = payload.get("compound_surnames", [])
    single_tiers_raw = payload.get("single_surname_tiers", {})
    boostable_raw = payload.get("boostable_medium_surnames", [])
    blacklist_raw = payload.get("boost_blacklist_phrases", {})
    given_raw = payload.get("zh_given_names", [])
    scoring_raw = payload.get("scoring", {})
    thresholds_raw = payload.get("submit_thresholds", {})

    if not isinstance(compound_raw, list):
        raise ValueError("zh_name_rules.json 格式错误：compound_surnames 应为数组。")
    if not isinstance(single_tiers_raw, dict):
        raise ValueError("zh_name_rules.json 格式错误：single_surname_tiers 应为对象。")
    if not isinstance(boostable_raw, list):
        raise ValueError("zh_name_rules.json 格式错误：boostable_medium_surnames 应为数组。")
    if not isinstance(blacklist_raw, dict):
        raise ValueError("zh_name_rules.json 格式错误：boost_blacklist_phrases 应为对象。")
    if not isinstance(given_raw, list):
        raise ValueError("zh_name_rules.json 格式错误：zh_given_names 应为数组。")
    if not isinstance(scoring_raw, dict):
        raise ValueError("zh_name_rules.json 格式错误：scoring 应为对象。")
    if not isinstance(thresholds_raw, dict):
        raise ValueError("zh_name_rules.json 格式错误：submit_thresholds 应为对象。")

    compound_surnames = tuple(
        sorted(
            {str(item).strip() for item in compound_raw if str(item).strip()},
            key=len,
            reverse=True,
        )
    )
    single_surname_tiers: dict[str, frozenset[str]] = {}
    surname_tier_by_char: dict[str, str] = {}
    for tier in ("strong", "medium", "weak"):
        raw_values = single_tiers_raw.get(tier, [])
        if not isinstance(raw_values, list):
            raise ValueError(f"zh_name_rules.json 格式错误：single_surname_tiers.{tier} 应为数组。")
        values = frozenset(str(item).strip() for item in raw_values if str(item).strip())
        single_surname_tiers[tier] = values
        for char in values:
            surname_tier_by_char[char] = tier

    boostable_medium_surnames = frozenset(str(item).strip() for item in boostable_raw if str(item).strip())
    boost_blacklist_phrases: dict[str, tuple[str, ...]] = {}
    for surname, phrases in blacklist_raw.items():
        if not isinstance(phrases, list):
            raise ValueError("zh_name_rules.json 格式错误：boost_blacklist_phrases 的值应为数组。")
        cleaned = tuple(
            sorted(
                {str(item).strip() for item in phrases if str(item).strip()},
                key=len,
                reverse=True,
            )
        )
        if cleaned:
            boost_blacklist_phrases[str(surname).strip()] = cleaned

    zh_given_names = tuple(
        sorted(
            {str(item).strip() for item in given_raw if str(item).strip()},
            key=len,
            reverse=True,
        )
    )
    given_name_tail_chars = frozenset(name[-1] for name in zh_given_names if len(name) >= 2 and _is_cjk(name[-1]))

    scoring = ZhNameScoreWeights(
        compound_exact_match=int(scoring_raw.get("compound_exact_match", 6)),
        single_strong=int(scoring_raw.get("single_strong", 3)),
        single_medium=int(scoring_raw.get("single_medium", 1)),
        single_weak=int(scoring_raw.get("single_weak", -2)),
        boostable_medium_after_blacklist_pass=int(scoring_raw.get("boostable_medium_after_blacklist_pass", 2)),
        position_first_char_of_2_to_3_char_cjk_span=int(scoring_raw.get("position_first_char_of_2_to_3_char_cjk_span", 2)),
        common_given_name_char_after_surname=int(scoring_raw.get("common_given_name_char_after_surname", 2)),
        name_field_or_contact_context=int(scoring_raw.get("name_field_or_contact_context", 3)),
        fixed_phrase_blacklist_hit=int(scoring_raw.get("fixed_phrase_blacklist_hit", -4)),
        non_name_field_context=int(scoring_raw.get("non_name_field_context", -2)),
    )
    thresholds = ZhNameSubmitThresholds(
        strong=int(thresholds_raw.get("strong", 4)),
        balanced=int(thresholds_raw.get("balanced", 5)),
        weak=int(thresholds_raw.get("weak", 6)),
    )
    return ZhNameRules(
        compound_surnames=compound_surnames,
        single_surname_tiers=single_surname_tiers,
        surname_tier_by_char=surname_tier_by_char,
        boostable_medium_surnames=boostable_medium_surnames,
        boost_blacklist_phrases=boost_blacklist_phrases,
        zh_given_names=zh_given_names,
        given_name_tail_chars=given_name_tail_chars,
        scoring=scoring,
        submit_thresholds=thresholds,
    )


class ZhNameCommitScorer:
    """中文 soft-name 唯一提交判定入口。"""

    def __init__(self, rules: ZhNameRules) -> None:
        self._rules = rules

    def evaluate(
        self,
        *,
        candidate_text: str,
        start: int,
        end: int,
        seed_clue: Clue,
        protection_level: ProtectionLevel,
        name_clues: list[tuple[int, Clue]],
        negative_clues: tuple[Clue, ...],
    ) -> ZhNameScoreDecision:
        compact_candidate = compact_zh_name_text(candidate_text)
        if len(compact_candidate) < 2 or not all(_is_cjk(char) for char in compact_candidate):
            return ZhNameScoreDecision(should_commit=False, total_score=0, threshold=self._rules.submit_thresholds.for_level(protection_level), reasons=("candidate_not_compact_cjk",))

        surname_match = self._match_prefix_surname(compact_candidate=compact_candidate, start=start, name_clues=name_clues)
        threshold = self._rules.submit_thresholds.for_level(protection_level)
        if surname_match is None:
            return ZhNameScoreDecision(should_commit=False, total_score=0, threshold=threshold, reasons=("missing_surname_anchor",))

        if len(compact_candidate) <= len(surname_match.text):
            return ZhNameScoreDecision(
                should_commit=False,
                total_score=surname_match.base_score,
                threshold=threshold,
                matched_surname=surname_match.text,
                surname_match_kind=surname_match.match_kind,
                surname_tier=surname_match.tier,
                surname_score=surname_match.base_score,
                reasons=("surname_only_candidate",),
            )

        if any(clue.start > start for clue in negative_clues):
            return ZhNameScoreDecision(
                should_commit=False,
                total_score=surname_match.base_score,
                threshold=threshold,
                matched_surname=surname_match.text,
                surname_match_kind=surname_match.match_kind,
                surname_tier=surname_match.tier,
                surname_score=surname_match.base_score,
                reasons=("tail_negative_overlap",),
            )

        surname_score = surname_match.base_score
        reasons: list[str] = [f"surname:{surname_match.match_kind}:{surname_match.tier}"]
        fixed_phrase_penalty = 0
        blacklist_phrases = self._rules.boost_blacklist_phrases.get(surname_match.text, ())
        if blacklist_phrases:
            exact_hit = any(compact_candidate == phrase for phrase in blacklist_phrases)
            prefix_hit = any(compact_candidate.startswith(phrase) for phrase in blacklist_phrases)
            if surname_match.tier == "medium" and surname_match.text in self._rules.boostable_medium_surnames:
                if prefix_hit:
                    fixed_phrase_penalty = self._rules.scoring.fixed_phrase_blacklist_hit
                    reasons.append("boost_blacklist_prefix_hit")
                else:
                    surname_score = self._rules.scoring.boostable_medium_after_blacklist_pass
                    reasons.append("boosted_medium_surname")
            elif exact_hit:
                fixed_phrase_penalty = self._rules.scoring.fixed_phrase_blacklist_hit
                reasons.append("fixed_phrase_exact_hit")

        exact_negative_penalty = 0
        if seed_clue.role != ClueRole.START and any(compact_zh_name_text(clue.text) == compact_candidate for clue in negative_clues):
            exact_negative_penalty = self._rules.scoring.fixed_phrase_blacklist_hit
            reasons.append("exact_negative_match")

        seed_context_score = self._seed_context_score(seed_clue)
        if seed_context_score:
            reasons.append(f"seed_context:{seed_context_score}")

        shape_score = 0
        if 2 <= len(compact_candidate) <= 3:
            shape_score = self._rules.scoring.position_first_char_of_2_to_3_char_cjk_span
            reasons.append("compact_2_to_3_char_shape")

        given_name_evidence_score = 0
        if self._has_given_name_evidence(
            compact_candidate=compact_candidate,
            surname_text=surname_match.text,
            start=start,
            end=end,
            name_clues=name_clues,
        ):
            given_name_evidence_score = self._rules.scoring.common_given_name_char_after_surname
            reasons.append("given_name_evidence")

        total_score = surname_score + seed_context_score + shape_score + given_name_evidence_score + fixed_phrase_penalty + exact_negative_penalty
        return ZhNameScoreDecision(
            should_commit=total_score >= threshold,
            total_score=total_score,
            threshold=threshold,
            matched_surname=surname_match.text,
            surname_match_kind=surname_match.match_kind,
            surname_tier=surname_match.tier,
            surname_score=surname_score,
            seed_context_score=seed_context_score,
            shape_score=shape_score,
            given_name_evidence_score=given_name_evidence_score,
            fixed_phrase_penalty=fixed_phrase_penalty + exact_negative_penalty,
            reasons=tuple(reasons),
        )

    def _match_prefix_surname(
        self,
        *,
        compact_candidate: str,
        start: int,
        name_clues: list[tuple[int, Clue]],
    ) -> ZhSurnameMatch | None:
        for compound in self._rules.compound_surnames:
            if compact_candidate.startswith(compound):
                return ZhSurnameMatch(
                    text=compound,
                    match_kind="compound",
                    tier="compound",
                    base_score=self._rules.scoring.compound_exact_match,
                )

        single = compact_candidate[0]
        tier = self._rules.surname_tier_by_char.get(single)
        if tier is not None:
            return ZhSurnameMatch(
                text=single,
                match_kind="single",
                tier=tier,
                base_score=self._score_for_single_tier(tier),
            )

        for _index, clue in name_clues:
            if clue.role != ClueRole.FAMILY_NAME or clue.start != start:
                continue
            tier_values = clue.source_metadata.get("surname_tier", [])
            if not tier_values:
                continue
            tier_value = str(tier_values[0]).strip().lower()
            if tier_value != "custom":
                continue
            surname_text = compact_zh_name_text(clue.text)
            if not surname_text or not compact_candidate.startswith(surname_text):
                continue
            match_kind = "compound" if len(surname_text) > 1 else "single"
            return ZhSurnameMatch(
                text=surname_text,
                match_kind=match_kind,
                tier="custom",
                base_score=self._rules.scoring.single_strong,
                from_dictionary=True,
            )
        return None

    def _has_given_name_evidence(
        self,
        *,
        compact_candidate: str,
        surname_text: str,
        start: int,
        end: int,
        name_clues: list[tuple[int, Clue]],
    ) -> bool:
        tail = compact_candidate[len(surname_text) :]
        if tail and tail in self._rules.zh_given_names:
            return True
        if tail and tail[0] in self._rules.given_name_tail_chars:
            return True
        raw_given_start = start + len(surname_text)
        for _index, clue in name_clues:
            if clue.role != ClueRole.GIVEN_NAME:
                continue
            if clue.start >= raw_given_start and clue.end <= end:
                return True
        return False

    def _seed_context_score(self, clue: Clue) -> int:
        if clue.role not in _SEED_CONTEXT_ROLES:
            return 0
        values = clue.source_metadata.get("seed_context_score", [])
        if not values:
            return 0
        try:
            return int(values[0])
        except ValueError:
            return 0

    def _score_for_single_tier(self, tier: str) -> int:
        if tier == "strong":
            return self._rules.scoring.single_strong
        if tier == "medium":
            return self._rules.scoring.single_medium
        if tier == "weak":
            return self._rules.scoring.single_weak
        return self._rules.scoring.single_strong


__all__ = [
    "ZhNameCommitScorer",
    "ZhNameRules",
    "ZhNameScoreDecision",
    "ZhNameScoreWeights",
    "ZhNameSubmitThresholds",
    "ZhSurnameMatch",
    "build_zh_name_rules",
    "compact_zh_name_text",
]

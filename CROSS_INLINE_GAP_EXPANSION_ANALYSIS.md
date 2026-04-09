# PII Detection Stack Expansion & Gap Logic Analysis

## Overview
Detailed analysis of expansion/forward-scanning logic across PII detection stacks.

## 1. Unit Model & Character Mapping (models.py)

StreamUnit has:
- kind: str (unit type)
- text: str (content)
- char_start: int (inclusive)
- char_end: int (exclusive)

Common unit kinds:
- "ascii_word", "space", "cjk_char", "punct", "digit_run"
- "inline_gap", "ocr_break", "word"

StreamInput has char_to_unit: tuple[int, ...] mapping char positions to unit indices.

## 2. Address Stack (address.py) 

Main loop (lines 236-366):
- Iterates through clues starting at scan_index
- UNIT-BASED GAP CHECK at lines 272-275:
  gap_anchor = max(last_consumed_address_clue.unit_end, absorbed_digit_unit_end)
  if clue.unit_start - gap_anchor > 6:
    break

- Gap measured in UNITS, threshold is 6 units
- All unit types count (space, punct, words, etc.)

_has_nearby_address_clue() (lines 589-612):
- Hard char limit: 30 characters
- English: gap > 3 words = stop
- Chinese: gap > 6 chars = stop

_build_value_key_component() (lines 630-663):
- English: gap must be spaces only (^[ ]*$)
- Chinese: no gap allowed

_resolve_label_upper_boundary() in Organization (lines 131-144):
  if unit.kind in {"inline_gap", "ocr_break"}:
    return unit.char_start  # IMMEDIATE STOP

## 3. Name Stack (name.py)

_expand_seed_right() (lines 134-185):
- Finds next component clue and blocker
- Computes upper boundary (earliest blocker or component)
- Calls _scan_plain_right() to expand
- If at component boundary, consumes it and chains
- NO unit-based gap counting between components

_scan_plain_right() (lines 248-308):
- Chinese: counts CJK chars (max 4)
- English: consumes ascii_word, spaces (if followed by word), joiners
- Hard limit: 80 chars total
- No explicit gap size limit

_extend_given_chain_right_en() (lines 187-216):
- Chains GIVEN_NAME components (English only)
- CALLS _gap_allows_single_plain_word() for each gap

_gap_allows_single_plain_word() (lines 352-374):
- Returns True if gap contains 0 or 1 ascii_word
- Rejects if word_count > 1
- Rejects any non-space, non-word unit
- Rejects any clue overlap

## 4. Organization Stack (organization.py)

_resolve_label_end() (lines 108-120):
- Gets upper boundary (checks inline_gap!)
- Extends right with unit-based limit

_resolve_label_upper_boundary() (lines 131-144):
  while ui < len(units):
    unit = units[ui]
    if unit.kind in {"inline_gap", "ocr_break"}:
      return unit.char_start  # STOP IMMEDIATELY
    ...

_extend_organization_right_with_limit() (lines 231-265):
- Count units: ascii_word (EN) or cjk_char (ZH)
- Limit: 4 (EN) or 6 (ZH)
- Spaces/punct sticky (included if content exists)

## 5. Common Helpers (common.py)

_unit_index_at_or_after(stream, char_index) -> int
_unit_index_left_of(stream, char_index) -> int
_unit_char_start(stream, unit_index) -> int
_unit_char_end(stream, unit_index) -> int
_count_non_space_units(units, start_ui, end_ui) -> int
_char_span_to_unit_span(stream, start, end) -> (unit_start, unit_end)

## 6. Gap Measurement Summary

Address: Unit-based gap > 6 units = STOP
Name: _gap_allows_single_plain_word() for component chains
Organization: inline_gap/ocr_break = IMMEDIATE STOP

## 7. Inline Gap Handling

ONLY Organization checks for inline_gap in _resolve_label_upper_boundary():
- Line 139: if unit.kind in {"inline_gap", "ocr_break"}

Address & Name stacks do NOT check inline_gap.

## 8. Implementation Strategy

Create _gap_unit_composition() to analyze:
- What units are in a gap
- Whether gap contains only "soft" units (space, inline_gap)
- Whether gap contains "hard" units (content, breaks)

Modify:
1. Address run(): Use composition analysis for relaxed limits
2. Name _gap_allows_single_plain_word(): Treat inline_gap as invisible
3. Organization: Distinguish soft vs hard gap types

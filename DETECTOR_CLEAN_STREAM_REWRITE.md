# Detector Clean Stream Rewrite

## Goal

Replace the current `events -> proposal -> conflict` detector path with a clean stream architecture:

1. `scanner` only finds clue points.
2. `parser` only maintains one main stack and at most one challenger stack.
3. `stack` only resolves left boundary, right boundary, extracts value, normalizes value, and commits.
4. No local-region regex re-scan after the global hard-regex pass.

## Pipeline

```text
prompt / ocr stream
-> scanner
-> clue bundle
-> stream parser
-> stack finalize
-> candidate drafts
-> ocr geometry bind
-> pii candidates
```

## Scanner Layer

Scanner only produces `Clue`.

### Hard clues

Hard clues are found exactly once on the whole text:

- phone
- email
- id_number
- passport
- driver_license
- bank_account
- card_number
- session dictionary hits
- local dictionary hits

Once a hard clue is found:

- emit a `hard clue`
- reserve its raw span
- replace its visible text in `shadow_text` with a placeholder

Hard clues are the only clues that may directly become hard candidates.

### Soft clues

Soft clues only mark line-of-thought points:

- `name_label`
- `address_label`
- `phone_label`
- `email_label`
- `id_label`
- `passport_label`
- `driver_license_label`
- `organization_label`
- `company_suffix`
- `address_value_province`
- `address_value_city`
- `address_value_district`
- `address_key_province`
- `address_key_city`
- `address_key_district`
- `address_key_road`
- `address_key_compound`
- `address_key_building`
- `address_key_unit`
- `address_key_floor`
- `address_key_room`
- `family_name`
- `name_start`
- `break`

### Scanner rules

- Scanner never emits final candidates.
- Scanner never performs local-region regex after a clue is found.
- Address `name` clues only come from geo-db hits.
- Address `attr` clues only come from fixed keyword tables.
- Name clues come from label, surname, or self-introduction keywords.
- Organization clues come from label or suffix keywords.
- `break` clues come from OCR semantic breaks, strong punctuation, and unskippable separators.

## Clue Model

```python
@dataclass(slots=True)
class Clue:
    clue_id: str
    family: str
    kind: str
    start: int
    end: int
    text: str
    priority: int
    hard: bool
    attr_type: PIIAttributeType | None
    payload: dict[str, object]
```

### Families

- `structured`
- `address`
- `name`
- `organization`
- `break`

## Parser Layer

Parser owns:

- a clue pointer
- one `current_stack`
- optionally one `challenger_stack`
- committed drafts
- committed raw boundary

### Parser invariants

- At most one main stack exists.
- At most one challenger stack exists.
- Only one challenger creation rule exists in the first version:
  - if the next unresolved clue belongs to a different family than the current main stack family, allow challenger creation at that clue.
- Same-family next clues must be consumed by the main stack, not by opening a new sibling stack.
- Any region strictly before the committed boundary is final and cannot be re-opened.

## Stack Contract

Each stack follows the same lifecycle:

1. open from a clue
2. resolve left boundary
3. resolve right boundary by jumping clue-to-clue
4. extract the final raw slice once
5. normalize value once
6. commit immediately

Stacks are not allowed to:

- cut a region and then run regex inside that region
- emit multiple parallel draft attempts for the same seed
- reopen previously committed text

## StructuredValueStack

### Open clues

- hard structured clue
- structured label clue

### Rules

- Hard structured clue commits directly.
- Structured label does not run regex again.
- It only binds the nearest same-attr hard clue on the right if the path to that hard clue is not blocked by `break` or an incompatible clue.

## AddressStack

### Open clues

- `address_label`
- `address_value_*`
- `address_key_*`

### Left boundary

- `address_label`: start on the first non-separator char right of the label.
- `address_value_*`: start on the clue start.
- `address_key_*`: left-expand with address-specific rules until a hard stop, break clue, or incompatible family clue.

### Right boundary

- Move from the current component to the next clue.
- If the next clue is still an address clue and the gap is skippable, extend the right boundary directly to that clue end.
- If the next clue belongs to another family, stop extension and let parser decide whether a challenger should appear.
- If the gap contains a hard stop, stop.

### Metadata accumulation

Address metadata is accumulated inside the stack when the stack reaches each address key clue.

Example:

```text
四川省成都市阳光小区14栋103室
```

Scanner emits:

- `province_name = 四川`
- `province_attr = 省`
- `city_name = 成都`
- `city_attr = 市`
- `compound_attr = 小区`
- `building_attr = 栋`
- `room_attr = 室`

Address stack processing:

- reach `省` -> component `四川省` -> metadata `province:四川`
- reach `市` -> component `成都市` -> metadata `city:成都`
- reach `小区` -> component `阳光小区` -> metadata `compound:阳光`
- reach `栋` -> component `14栋` -> metadata `building:14`
- reach `室` -> component `103室` -> metadata `room:103`

Final output:

- one main `ADDRESS`
- metadata components only
- no standalone component candidates

## NameStack

### Open clues

- `name_label`
- `family_name`
- `name_start`

### Rules

- `name_label` and `name_start` start from the right side of the clue.
- `family_name` starts from the clue start.
- Right boundary extends through same-family name clues only.
- Stop when the next clue belongs to another family or is a hard/break clue.

## OrganizationStack

### Open clues

- `organization_label`
- `company_suffix`

### Rules

- `organization_label` starts from the right side of the label.
- `company_suffix` left-expands to the nearest compatible textual boundary.
- Right boundary normally ends at suffix end, unless the next clue is still an organization clue and the gap is skippable.

## Conflict Handling

Conflict handling is parser-owned.

The first version supports:

- hard vs soft
- address vs organization
- name vs organization
- name vs address

Conflict is only evaluated between:

- the current main stack result
- the challenger stack result

The parser never runs global candidate-pool overlap resolution.

## OCR Layer

OCR is still a post-text layer:

- text parsing produces text-level drafts
- OCR geometry remaps drafts back to blocks
- unresolved OCR labels may bind to right/down blocks

OCR geometry is not allowed to re-run text regex.

## Files

The clean implementation uses:

- `privacyguard/infrastructure/pii/detector/scanner.py`
- `privacyguard/infrastructure/pii/detector/parser.py`
- `privacyguard/infrastructure/pii/detector/stacks.py`
- `privacyguard/infrastructure/pii/detector/models.py`
- `privacyguard/infrastructure/pii/detector/rule_based.py`

The old `events.py` path is no longer part of the active main chain.

## Migration Order

1. add clue models
2. implement scanner
3. replace parser with single-main/single-challenger state machine
4. rewrite stacks to boundary-first processing
5. rewire `rule_based.py`
6. keep OCR only as a post-parse geometry layer

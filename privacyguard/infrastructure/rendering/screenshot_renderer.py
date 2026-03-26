"""截图渲染器实现。填充逻辑由注入的 ScreenshotFillStrategy 提供（与 decision 一致：按模式注册、工厂构建）。"""

from privacyguard.infrastructure.rendering.screenshot_renderer_shared import *
import privacyguard.infrastructure.rendering.screenshot_renderer_draw_items as _draw_items
import privacyguard.infrastructure.rendering.screenshot_renderer_layout as _layout


class ScreenshotRenderer:
    def __init__(
        self,
        fill_strategy: ScreenshotFillStrategy | None = None,
        background_color: str | None = None,
        text_color: str = "black",
    ) -> None:
        self._fill_strategy = fill_strategy or MixFillStrategy()
        self._fallback_bg = background_color or "white"
        self.text_color = text_color

    def render(
        self,
        image: Any,
        plan: DecisionPlan,
        ocr_blocks: list[OCRTextBlock] | None = None,
    ) -> Any:
        """将决策计划应用到截图并返回新图像。"""
        if image is None:
            return None
        pil_image = self._to_pil_image(image)
        if pil_image is None:
            LOGGER.warning("screenshot rendering skipped: Pillow unavailable or image input unsupported.")
            return image
        draw_items = self._build_draw_items(plan, ocr_blocks=ocr_blocks or [])
        pil_image, skip_fill_flags = self._fill_strategy.apply(pil_image, plan, draw_items)
        draw = self._create_draw(pil_image)
        for i, item in enumerate(draw_items):
            self._draw_text_box(
                draw=draw,
                item=item,
                image=pil_image,
                skip_fill=skip_fill_flags[i],
            )
        return pil_image

    _build_draw_items = _draw_items._build_draw_items
    _resolve_cross_block_ids = _draw_items._resolve_cross_block_ids
    _build_cross_block_draw_items = _draw_items._build_cross_block_draw_items
    _split_cross_block_replacement = _draw_items._split_cross_block_replacement
    _split_name_replacement_across_blocks = _draw_items._split_name_replacement_across_blocks
    _split_address_replacement_across_blocks = _draw_items._split_address_replacement_across_blocks
    _assign_name_units_by_source_overlap = _draw_items._assign_name_units_by_source_overlap
    _assign_address_units_by_source_overlap = _draw_items._assign_address_units_by_source_overlap
    _group_name_units_by_block_capacity = _draw_items._group_name_units_by_block_capacity
    _group_units_by_block_capacity = _draw_items._group_units_by_block_capacity
    _split_text_proportionally = _draw_items._split_text_proportionally
    _compact_name_segment = _draw_items._compact_name_segment
    _append_name_unit = _draw_items._append_name_unit
    _join_name_units = _draw_items._join_name_units
    _decorate_name_chunks = _draw_items._decorate_name_chunks
    _address_units = _draw_items._address_units
    _segment_ranges = _draw_items._segment_ranges
    _best_overlap_block = _draw_items._best_overlap_block
    _range_overlap = _draw_items._range_overlap
    _block_capacity = _draw_items._block_capacity
    _rebuild_block_text = _draw_items._rebuild_block_text
    _select_non_overlapping_actions = _draw_items._select_non_overlapping_actions
    _resolve_action_span = _draw_items._resolve_action_span
    _candidate_spans = _draw_items._candidate_spans
    _find_literal_spans = _draw_items._find_literal_spans
    _fallback_rebuild_block_text = _draw_items._fallback_rebuild_block_text
    _is_valid_span_action = _draw_items._is_valid_span_action
    _to_pil_image = _layout._to_pil_image
    _create_draw = _layout._create_draw
    _get_bbox_fill_color = _layout._get_bbox_fill_color
    _parse_fill = _layout._parse_fill
    _font_size_from_bbox_height = _layout._font_size_from_bbox_height
    _draw_text_box = _layout._draw_text_box
    _resolve_text_layout = _layout._resolve_text_layout
    _estimate_base_font_size = _layout._estimate_base_font_size
    _load_font = _layout._load_font
    _single_line_masks = _layout._single_line_masks
    _estimate_char_spacing = _layout._estimate_char_spacing
    _build_text_mask = _layout._build_text_mask
    _build_default_text_mask = _layout._build_default_text_mask
    _build_spaced_single_line_mask = _layout._build_spaced_single_line_mask
    _layout_from_mask = _layout._layout_from_mask
    _text_region_geometry = _layout._text_region_geometry
    _polygon_rotation = _layout._polygon_rotation
    _rotate_mask = _layout._rotate_mask
    _distance = _layout._distance
    _wrap_text_to_width = _layout._wrap_text_to_width
    _measure_multiline_text = _layout._measure_multiline_text
    _text_width = _layout._text_width

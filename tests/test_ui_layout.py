"""UI 结构理解层的单元测试。

覆盖四种典型布局场景：表格、流式、卡片、混合。
"""

from __future__ import annotations

import pytest

from privacyguard.domain.models.ocr import BoundingBox, OCRTextBlock
from privacyguard.infrastructure.pii.detector.ui_layout import (
    LayoutType,
    SemanticGroup,
    _build_segmented_lines,
    analyze_ui_layout,
    crop_blocks,
    detect_layout,
    group_into_lines,
    merge_flow,
    merge_table,
    split_into_regions,
    split_line_segments,
)


# ====================================================================
# 辅助工厂
# ====================================================================

def _b(text: str, x: int, y: int, w: int, h: int, *, block_id: str | None = None) -> OCRTextBlock:
    """快速构造一个 OCRTextBlock。"""
    return OCRTextBlock(
        text=text,
        bbox=BoundingBox(x=x, y=y, width=w, height=h),
        block_id=block_id,
    )


def _group_texts(groups: list[SemanticGroup]) -> list[str]:
    """提取各组的拼接文本，方便断言。"""
    return ["".join(b.text for b in g.blocks) for g in groups]


# ====================================================================
# ① 裁剪
# ====================================================================


class TestCropBlocks:
    def test_removes_top_and_bottom(self):
        """状态栏和导航栏区域的 blocks 应被裁掉。"""
        blocks = [
            _b("10:30", 100, 10, 60, 20),       # 顶部状态栏 y=10，截图高 1000 → 6% = 60
            _b("姓名", 20, 200, 60, 30),         # 中间内容
            _b("张三", 100, 200, 60, 30),        # 中间内容
            _b("首页", 100, 950, 60, 30),        # 底部导航栏 y+h=980 > 920 (92%)
        ]
        result = crop_blocks(blocks, image_height=1000)
        texts = [b.text for b in result]
        assert "10:30" not in texts
        assert "首页" not in texts
        assert "姓名" in texts
        assert "张三" in texts

    def test_infers_height_from_blocks(self):
        """未提供 image_height 时从 blocks 推断。"""
        blocks = [
            _b("顶部", 0, 5, 50, 20),    # y+h=25, 全高推断≈980
            _b("内容", 0, 200, 50, 20),
            _b("底部", 0, 960, 50, 20),   # y+h=980 → image_height=980
        ]
        result = crop_blocks(blocks)
        texts = [b.text for b in result]
        assert "内容" in texts

    def test_empty(self):
        assert crop_blocks([]) == []


# ====================================================================
# ② 分行
# ====================================================================


class TestGroupIntoLines:
    def test_same_line_different_sizes(self):
        """同行不同字号的 blocks（Y 有重叠）应归为一行。"""
        blocks = [
            _b("标签", 10, 100, 60, 20),
            _b("大值", 80, 95, 100, 30),   # 字号更大但 Y 重叠
        ]
        lines = group_into_lines(blocks)
        assert len(lines) == 1
        assert len(lines[0]) == 2

    def test_two_lines(self):
        blocks = [
            _b("行1", 10, 100, 60, 20),
            _b("行2", 10, 200, 60, 20),
        ]
        lines = group_into_lines(blocks)
        assert len(lines) == 2

    def test_sorted_by_x(self):
        """同行内应按 X 排序。"""
        blocks = [
            _b("右", 200, 100, 30, 20),
            _b("左", 10, 100, 30, 20),
        ]
        lines = group_into_lines(blocks)
        assert lines[0][0].text == "左"
        assert lines[0][1].text == "右"

    def test_empty_text_filtered(self):
        blocks = [
            _b("", 10, 100, 60, 20),
            _b("  ", 10, 200, 60, 20),
            _b("有效", 10, 300, 60, 20),
        ]
        lines = group_into_lines(blocks)
        assert len(lines) == 1
        assert lines[0][0].text == "有效"


# ====================================================================
# ③ 行内切分
# ====================================================================


class TestSplitLineSegments:
    def test_large_gap_splits(self):
        """行内大间距 → 切成两段。"""
        line = [
            _b("张三", 10, 100, 40, 20),
            _b("昨天14:30", 300, 100, 80, 20),  # x=300 远离 x=50
        ]
        segs = split_line_segments(line)
        assert len(segs) == 2
        assert segs[0][0].text == "张三"
        assert segs[1][0].text == "昨天14:30"

    def test_close_blocks_stay(self):
        """间距正常 → 不切分。"""
        line = [
            _b("张", 10, 100, 20, 20),
            _b("三", 32, 100, 20, 20),
        ]
        segs = split_line_segments(line)
        assert len(segs) == 1

    def test_single_block(self):
        line = [_b("单独", 10, 100, 40, 20)]
        segs = split_line_segments(line)
        assert len(segs) == 1


# ====================================================================
# ④ 区域分割
# ====================================================================


class TestSplitIntoRegions:
    def test_vertical_gap_splits(self):
        """大垂直间距 → 不同区域。"""
        blocks = [
            _b("A", 10, 100, 40, 20),
            _b("B", 10, 300, 40, 20),   # 间距 180 >> median_h(20) * 2
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        regions = split_into_regions(seg_lines)
        assert len(regions) == 2

    def test_multi_col_count_change_splits(self):
        """不同多列数之间跳变（2→3）→ 不同区域。"""
        blocks = [
            # 2 列行
            _b("姓名", 10, 100, 60, 20), _b("张三", 200, 100, 60, 20),
            # 3 列行（紧邻，间距足够大以切成 3 段）
            _b("A", 10, 125, 10, 20), _b("B", 200, 125, 10, 20), _b("C", 400, 125, 10, 20),
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        regions = split_into_regions(seg_lines)
        assert len(regions) == 2

    def test_n_to_1_not_split(self):
        """N↔1 的列数跳变不切割（可能是卡片模式）。"""
        blocks = [
            _b("张三", 10, 100, 60, 20), _b("昨天", 200, 100, 60, 20),
            _b("你好", 10, 125, 120, 20),
            _b("李四", 10, 150, 60, 20), _b("今天", 200, 150, 60, 20),
            _b("好的", 10, 175, 120, 20),
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        regions = split_into_regions(seg_lines)
        assert len(regions) == 1  # 全部在同一区域

    def test_aligned_columns_same_region(self):
        """列对齐的多行 → 同一区域。"""
        blocks = [
            _b("姓名", 10, 100, 60, 20), _b("张三", 200, 100, 60, 20),
            _b("电话", 10, 130, 60, 20), _b("138xxxx", 200, 130, 80, 20),
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        regions = split_into_regions(seg_lines)
        assert len(regions) == 1


# ====================================================================
# ⑤ 布局检测
# ====================================================================


class TestDetectLayout:
    def test_table_detected(self):
        """多行多列且列对齐 → TABLE。"""
        blocks = [
            _b("姓名", 10, 100, 60, 20), _b("张三", 200, 100, 60, 20),
            _b("电话", 10, 130, 60, 20), _b("138xxxx", 200, 130, 80, 20),
            _b("邮箱", 10, 160, 60, 20), _b("a@b.com", 200, 160, 80, 20),
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        assert detect_layout(seg_lines, 0, len(seg_lines)) == LayoutType.TABLE

    def test_chat_list_as_table(self):
        """聊天列表（2-1 交替）：多段行列对齐 → TABLE。"""
        blocks = [
            _b("张三", 10, 100, 60, 20), _b("昨天14:30", 200, 100, 80, 20),
            _b("你好，明天几点开会？", 10, 125, 180, 20),
            _b("李四", 10, 155, 60, 20), _b("今天09:15", 200, 155, 80, 20),
            _b("好的，下午两点", 10, 180, 140, 20),
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        assert detect_layout(seg_lines, 0, len(seg_lines)) == LayoutType.TABLE

    def test_flow_single_column(self):
        """单列行 → FLOW。"""
        blocks = [
            _b("地址：", 10, 100, 60, 20),
            _b("北京市朝阳区", 40, 130, 120, 20),
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        assert detect_layout(seg_lines, 0, len(seg_lines)) == LayoutType.FLOW


# ====================================================================
# ⑥ 流式拼接
# ====================================================================


class TestMergeFlow:
    def test_indent_subordination(self):
        """label 独占一行 + 缩进 value → 归入同组。"""
        blocks = [
            _b("收货地址：", 20, 100, 100, 20),
            _b("北京市朝阳区xxx路", 60, 130, 160, 20),
            _b("123号xxx小区", 60, 160, 120, 20),
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        groups = merge_flow(seg_lines, 0, len(seg_lines))
        assert len(groups) == 1
        texts = _group_texts(groups)
        assert "收货地址：" in texts[0]
        assert "北京市朝阳区xxx路" in texts[0]
        assert "123号xxx小区" in texts[0]

    def test_anchor_reset_on_new_label(self):
        """新 label 回到同级位置 → 新组。"""
        blocks = [
            _b("收货地址：", 20, 100, 100, 20),
            _b("北京市朝阳区", 60, 130, 120, 20),
            _b("联系电话：", 20, 165, 100, 20),  # 回到 x=20
            _b("13800001111", 60, 195, 120, 20),
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        groups = merge_flow(seg_lines, 0, len(seg_lines))
        assert len(groups) == 2

    def test_left_aligned_continuation(self):
        """左对齐续行 → 归入同组。"""
        blocks = [
            _b("北京市朝阳区望京街道", 20, 100, 200, 20),
            _b("阜通东大街6号院", 20, 130, 160, 20),  # 同 x1 → 续行
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        groups = merge_flow(seg_lines, 0, len(seg_lines))
        assert len(groups) == 1

    def test_far_gap_splits(self):
        """垂直间距过大 → 新组。"""
        blocks = [
            _b("内容A", 20, 100, 80, 20),
            _b("内容B", 20, 300, 80, 20),  # 间距 180 >> 阈值
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        groups = merge_flow(seg_lines, 0, len(seg_lines))
        assert len(groups) == 2


# ====================================================================
# ⑦ 表格拼接
# ====================================================================


class TestMergeTable:
    def test_rows_grouped(self):
        """表格按行横向拼接：每行一组，label 和 value 在同一组。"""
        blocks = [
            _b("姓名", 10, 100, 60, 20), _b("张三", 200, 100, 60, 20),
            _b("电话", 10, 130, 60, 20), _b("138xxxx", 200, 130, 80, 20),
            _b("邮箱", 10, 160, 60, 20), _b("a@b.com", 200, 160, 80, 20),
        ]
        lines = group_into_lines(blocks)
        seg_lines = _build_segmented_lines(lines)
        groups = merge_table(seg_lines, 0, len(seg_lines))
        assert len(groups) == 3  # 三行
        texts = _group_texts(groups)
        assert "姓名" in texts[0] and "张三" in texts[0]
        assert "电话" in texts[1] and "138xxxx" in texts[1]
        assert "邮箱" in texts[2] and "a@b.com" in texts[2]


# ====================================================================
# 聊天列表（N↔1 交替）集成测试
# ====================================================================


class TestChatListLayout:
    def test_chat_list_not_fragmented(self):
        """聊天列表 2-1-2-1 交替：每行一个组，不碎片化。"""
        blocks = [
            _b("张三", 10, 200, 60, 20), _b("昨天14:30", 200, 200, 80, 20),
            _b("你好，明天几点开会？", 10, 225, 180, 20),
            _b("李四", 10, 255, 60, 20), _b("今天09:15", 200, 255, 80, 20),
            _b("好的，下午两点", 10, 280, 140, 20),
        ]
        groups = analyze_ui_layout(blocks, image_height=1000)
        texts = _group_texts(groups)
        assert len(groups) == 4
        assert "张三" in texts[0] and "昨天14:30" in texts[0]
        assert "你好，明天几点开会？" in texts[1]
        assert "李四" in texts[2] and "今天09:15" in texts[2]
        assert "好的，下午两点" in texts[3]


# ====================================================================
# 主入口集成测试
# ====================================================================


class TestAnalyzeUILayout:
    def test_mixed_layout(self):
        """混合布局：上半部分表格 + 下半部分流式。"""
        blocks = [
            # 表格区域（3 行 × 2 列，列对齐）
            _b("姓名", 10, 200, 60, 20), _b("张三", 200, 200, 60, 20),
            _b("电话", 10, 230, 60, 20), _b("138xxxx", 200, 230, 80, 20),
            _b("邮箱", 10, 260, 60, 20), _b("a@b.com", 200, 260, 80, 20),
            # 大间距
            # 流式区域
            _b("备注：", 10, 400, 60, 20),
            _b("这是一段很长的备注文字", 40, 430, 200, 20),
        ]
        groups = analyze_ui_layout(blocks, image_height=1000)
        # 表格产生 2 列组 + 流式产生若干组。
        assert len(groups) >= 3
        all_text = "".join("".join(b.text for b in g.blocks) for g in groups)
        assert "张三" in all_text
        assert "备注：" in all_text

    def test_empty_input(self):
        assert analyze_ui_layout([]) == []

    def test_all_cropped(self):
        """所有 blocks 都在裁剪区域内 → 回退到空结果。"""
        blocks = [
            _b("10:30", 100, 10, 60, 20),   # 顶部
            _b("首页", 100, 960, 60, 20),    # 底部
        ]
        result = analyze_ui_layout(blocks, image_height=1000)
        assert result == []


# ====================================================================
# build_ocr_stream 集成测试
# ====================================================================


class TestBuildOcrStreamIntegration:
    def test_groups_separated_by_semantic_break(self):
        """不同语义组之间应有 semantic break，组内没有。"""
        from privacyguard.infrastructure.pii.detector.preprocess import build_ocr_stream
        from privacyguard.infrastructure.pii.rule_based_detector_shared import _OCR_SEMANTIC_BREAK_TOKEN

        blocks = [
            # 组 1：label + 缩进 value
            _b("地址：", 20, 200, 60, 20),
            _b("北京市朝阳区", 60, 230, 120, 20),
            # 组 2：新 label
            _b("电话：", 20, 265, 60, 20),
            _b("13800001111", 60, 295, 120, 20),
        ]
        prepared = build_ocr_stream(blocks, image_height=1000)
        text = prepared.stream.text
        # 应该有 semantic break 分隔两组。
        assert _OCR_SEMANTIC_BREAK_TOKEN in text
        # 组内（地址：和北京市朝阳区之间）不应有 semantic break。
        parts = text.split(_OCR_SEMANTIC_BREAK_TOKEN)
        addr_part = [p for p in parts if "地址" in p]
        assert addr_part
        assert "北京市朝阳区" in addr_part[0]

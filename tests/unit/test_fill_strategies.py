"""填充策略与背景分类回归测试。"""

from types import SimpleNamespace

from PIL import Image

from privacyguard.app.factories import DEFAULT_FILL_MODE, build_screenshot_fill_strategy, get_or_create_registry
from privacyguard.domain.enums import ActionType, PIIAttributeType
from privacyguard.domain.models.decision import DecisionAction, DecisionPlan
from privacyguard.domain.models.ocr import BoundingBox
from privacyguard.infrastructure.rendering import fill_strategies
from privacyguard.infrastructure.rendering.fill_strategies import CVFillStrategy, MixFillStrategy
from privacyguard.infrastructure.rendering.prompt_renderer import PromptRenderer
from privacyguard.infrastructure.rendering.screenshot_renderer import ScreenshotRenderer


def _demo_plan() -> DecisionPlan:
    return DecisionPlan(
        session_id="demo",
        turn_id=1,
        actions=[
            DecisionAction(
                candidate_id="cand-action",
                action_type=ActionType.GENERICIZE,
                attr_type=PIIAttributeType.NAME,
                replacement_text="李四",
                bbox=BoundingBox(x=1, y=1, width=10, height=10),
                reason="action",
            )
        ],
    )


def test_default_fill_mode_uses_mix_everywhere() -> None:
    registry = get_or_create_registry()

    strategy = build_screenshot_fill_strategy(DEFAULT_FILL_MODE, registry)

    assert DEFAULT_FILL_MODE == "mix"
    assert isinstance(strategy, MixFillStrategy)
    assert isinstance(ScreenshotRenderer()._fill_strategy, MixFillStrategy)
    assert isinstance(PromptRenderer().screenshot_renderer._fill_strategy, MixFillStrategy)


def test_cv_fill_strategy_uses_draw_items_instead_of_plan_actions(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_inpaint(image, items):
        captured["image"] = image
        captured["items"] = items
        return (image, True)

    monkeypatch.setattr(fill_strategies, "_inpaint_shapes", fake_inpaint)
    strategy = CVFillStrategy()
    image = object()
    draw_items = [SimpleNamespace(bbox=BoundingBox(x=20, y=20, width=30, height=30), text="整框重绘")]

    filled, skip_fill = strategy.apply(image, _demo_plan(), draw_items)

    assert filled is image
    assert skip_fill == [True]
    assert captured["items"] == draw_items


def test_cv_fill_strategy_falls_back_to_gradient_when_inpaint_unavailable(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_inpaint(image, items):
        captured["inpaint_items"] = items
        return (image, False)

    def fake_gradient_apply(self, image, plan, draw_items):
        captured["gradient_items"] = draw_items
        return (image, [True] * len(draw_items))

    monkeypatch.setattr(fill_strategies, "_inpaint_shapes", fake_inpaint)
    monkeypatch.setattr(fill_strategies.GradientFillStrategy, "apply", fake_gradient_apply)
    strategy = CVFillStrategy()
    image = object()
    draw_items = [SimpleNamespace(bbox=BoundingBox(x=20, y=20, width=30, height=30), text="整框重绘")]

    filled, skip_fill = strategy.apply(image, _demo_plan(), draw_items)

    assert filled is image
    assert skip_fill == [True]
    assert captured["inpaint_items"] == draw_items
    assert captured["gradient_items"] == draw_items


def test_mix_fill_strategy_uses_ring_pixels_instead_of_bbox_interior(monkeypatch) -> None:
    called: dict[str, bool] = {"inpaint": False}

    def fake_inpaint(image, items):
        called["inpaint"] = True
        return (image, True)

    monkeypatch.setattr(fill_strategies, "_inpaint_shapes", fake_inpaint)
    strategy = MixFillStrategy()
    image = Image.new("RGB", (24, 24), "white")
    for y in range(8, 16):
        for x in range(8, 16):
            value = 0 if (x + y) % 2 == 0 else 255
            image.putpixel((x, y), (value, value, value))
    draw_items = [SimpleNamespace(bbox=BoundingBox(x=8, y=8, width=8, height=8), text="张三")]

    filled, skip_fill = strategy.apply(image, _demo_plan(), draw_items)

    assert skip_fill == [True]
    assert called["inpaint"] is False
    assert filled.getpixel((11, 11)) == (255, 255, 255)


def test_mix_fill_strategy_prefers_gradient_before_inpaint(monkeypatch) -> None:
    called: dict[str, bool] = {"inpaint": False}

    def fake_inpaint(image, items):
        called["inpaint"] = True
        return (image, True)

    monkeypatch.setattr(fill_strategies, "_inpaint_shapes", fake_inpaint)
    strategy = MixFillStrategy()
    image = Image.new("RGB", (30, 30), "white")
    for y in range(30):
        shade = 60 + y * 4
        for x in range(30):
            image.putpixel((x, y), (shade, shade, shade))
    for y in range(10, 20):
        for x in range(10, 20):
            image.putpixel((x, y), (0, 0, 0))
    draw_items = [SimpleNamespace(bbox=BoundingBox(x=10, y=10, width=10, height=10), text="张三")]

    filled, skip_fill = strategy.apply(image, _demo_plan(), draw_items)

    assert skip_fill == [True]
    assert called["inpaint"] is False
    assert filled.getpixel((15, 11))[0] < filled.getpixel((15, 18))[0]

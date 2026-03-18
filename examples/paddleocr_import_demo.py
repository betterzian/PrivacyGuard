"""PP-OCRv5 官方 import 方式示例。"""


def main() -> None:
    """演示 PaddleOCR 官方 Python 调用方式。"""
    from paddleocr import PaddleOCR

    ocr = PaddleOCR(
        use_doc_orientation_classify=False,
        use_doc_unwarping=False,
        use_textline_orientation=False,
    )

    result = ocr.predict(
        input="https://paddle-model-ecology.bj.bcebos.com/paddlex/imgs/demo_image/general_ocr_002.png"
    )
    for res in result:
        res.print()
        res.save_to_img("output")
        res.save_to_json("output")


if __name__ == "__main__":
    main()

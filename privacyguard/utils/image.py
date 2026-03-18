"""图像输入兼容与校验工具。"""

from pathlib import Path
from urllib.parse import urlparse
from typing import Any


def _is_pil_image(image: Any) -> bool:
    """判断输入是否为 PIL.Image.Image。"""
    try:
        from PIL import Image
    except Exception:
        return False
    return isinstance(image, Image.Image)


def _is_numpy_array(image: Any) -> bool:
    """判断输入是否为 numpy.ndarray。"""
    try:
        import numpy as np
    except Exception:
        return False
    return isinstance(image, np.ndarray)


def _is_existing_file_path(image: Any) -> bool:
    """判断输入是否为存在的本地文件路径。"""
    if not isinstance(image, (str, Path)):
        return False
    return Path(image).exists()


def _is_remote_image_url(image: Any) -> bool:
    """判断输入是否为可直接交给 PaddleOCR 的远程图片 URL。"""
    if not isinstance(image, str):
        return False
    parsed = urlparse(image)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def ensure_supported_image_input(image: Any, *, allow_remote_url: bool = True) -> Any:
    """校验图像输入类型并返回原值。

    支持 PIL.Image.Image、numpy.ndarray、本地文件路径，以及可直接交给 PaddleOCR 的远程图片 URL。
    """
    if _is_pil_image(image):
        return image
    if _is_numpy_array(image):
        return image
    if _is_existing_file_path(image):
        return Path(image)
    if allow_remote_url and _is_remote_image_url(image):
        return str(image)
    raise ValueError("不支持的图像输入类型，仅支持 PIL.Image.Image、numpy.ndarray、存在的本地文件路径或 http(s) URL。")

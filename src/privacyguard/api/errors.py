"""API 层错误定义。"""


class PrivacyGuardError(Exception):
    """PrivacyGuard 业务错误基类。"""


class InvalidConfigurationError(PrivacyGuardError):
    """配置缺失或配置非法时抛出。"""


class ComponentNotRegisteredError(PrivacyGuardError):
    """组件未注册或查找失败时抛出。"""


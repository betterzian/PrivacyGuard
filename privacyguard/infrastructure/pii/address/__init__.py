"""结构化地址检测能力。"""

__all__ = ["collect_address_candidates"]


def __getattr__(name: str):
    if name != "collect_address_candidates":
        raise AttributeError(name)
    from privacyguard.infrastructure.pii.address.pipeline import collect_address_candidates

    return collect_address_candidates

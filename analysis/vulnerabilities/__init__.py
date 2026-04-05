from __future__ import annotations

from analysis.common.debug import logger


def stub_disabled_detector(detector_name: str, *args, **kwargs) -> list[dict]:
    logger.warning("%s detector temporarily disabled (IR pipeline removed)", detector_name)
    return []

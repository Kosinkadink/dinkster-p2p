"""P2P runtime settings shared by the host and sidecar."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import cast

P2P_SETTINGS_FIELDS = frozenset(
    {
        "downloadsEnabled",
        "seedingEnabled",
        "scope",
        "internetUploadBytesPerSecond",
        "internetDownloadBytesPerSecond",
        "lanUploadBytesPerSecond",
        "lanDownloadBytesPerSecond",
        "pauseOnMetered",
        "networkCostOverride",
        "seedMode",
        "internetSeedRatio",
        "internetSeedTimeSeconds",
        "stagingBudgetBytes",
    }
)
P2P_SCOPES = frozenset({"lan-only", "lan-and-internet"})
NETWORK_COST_OVERRIDES = frozenset({"auto", "metered", "unmetered"})
SEED_MODES = frozenset({"budgeted", "continuous"})
_MAX_INTEGER_SETTING = 2_147_483_647


class P2PSettingsError(ValueError):
    """A P2P settings object is malformed."""


def default_p2p_settings() -> dict[str, object]:
    return {
        "downloadsEnabled": False,
        "seedingEnabled": False,
        "scope": "lan-and-internet",
        "internetUploadBytesPerSecond": 5_242_880,
        "internetDownloadBytesPerSecond": 0,
        "lanUploadBytesPerSecond": 0,
        "lanDownloadBytesPerSecond": 0,
        "pauseOnMetered": True,
        "networkCostOverride": "auto",
        "seedMode": "budgeted",
        "internetSeedRatio": 1.0,
        "internetSeedTimeSeconds": 86_400,
        "stagingBudgetBytes": 64 * 1024**3,
    }


def normalize_p2p_settings(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise P2PSettingsError("p2p must be an object")
    body = {str(key): item for key, item in cast("Mapping[object, object]", value).items()}
    # Fill only the added field; persisted enable/scope choices remain authoritative.
    body.setdefault("stagingBudgetBytes", default_p2p_settings()["stagingBudgetBytes"])
    if set(body) != set(P2P_SETTINGS_FIELDS):
        raise P2PSettingsError(
            f"p2p must contain exactly {sorted(P2P_SETTINGS_FIELDS)}, got {sorted(body)}"
        )
    for field in ("downloadsEnabled", "seedingEnabled", "pauseOnMetered"):
        if not isinstance(body[field], bool):
            raise P2PSettingsError(f"p2p.{field} must be a boolean")
    choices = {
        "scope": P2P_SCOPES,
        "networkCostOverride": NETWORK_COST_OVERRIDES,
        "seedMode": SEED_MODES,
    }
    for field, allowed in choices.items():
        if not isinstance(body[field], str) or body[field] not in allowed:
            raise P2PSettingsError(f"p2p.{field} must be one of {sorted(allowed)}")
    for field in (
        "internetUploadBytesPerSecond",
        "internetDownloadBytesPerSecond",
        "lanUploadBytesPerSecond",
        "lanDownloadBytesPerSecond",
        "internetSeedTimeSeconds",
    ):
        if (
            type(body[field]) is not int
            or cast(int, body[field]) < 0
            or cast(int, body[field]) > _MAX_INTEGER_SETTING
        ):
            raise P2PSettingsError(
                f"p2p.{field} must be an integer from 0 through {_MAX_INTEGER_SETTING}"
            )
    if type(body["stagingBudgetBytes"]) is not int or not (
        0 <= body["stagingBudgetBytes"] <= 2**53 - 1
    ):
        raise P2PSettingsError("p2p.stagingBudgetBytes must be a non-negative safe integer")
    ratio = body["internetSeedRatio"]
    if isinstance(ratio, bool) or not isinstance(ratio, (int, float)):
        raise P2PSettingsError("p2p.internetSeedRatio must be a finite non-negative number")
    try:
        normalized_ratio = float(ratio)
    except OverflowError as error:
        raise P2PSettingsError(
            "p2p.internetSeedRatio must be a finite non-negative number"
        ) from error
    if not math.isfinite(normalized_ratio) or normalized_ratio < 0:
        raise P2PSettingsError("p2p.internetSeedRatio must be a finite non-negative number")
    body["internetSeedRatio"] = normalized_ratio
    return body

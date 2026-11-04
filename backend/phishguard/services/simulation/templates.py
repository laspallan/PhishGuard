"""Template management for simulations."""

from __future__ import annotations

from enum import StrEnum


class TemplateType(StrEnum):
    TRAINING = "training"
    SIM_HOLDOUT = "sim_holdout"

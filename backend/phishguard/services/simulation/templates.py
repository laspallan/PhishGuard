"""Template management for simulations."""
from __future__ import annotations

from enum import Enum


class TemplateType(str, Enum):
    TRAINING = "training"
    SIM_HOLDOUT = "sim_holdout"

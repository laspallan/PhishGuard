"""The one missing value for every feature (decision P2-a).

Used both for "does not apply to this record" (e.g. email features on a URL) and for "could not
be measured" (e.g. no RDAP data). XGBoost and LightGBM handle NaN natively.
"""

import math

MISSING: float = math.nan


def is_missing(value: float) -> bool:
    return math.isnan(value)

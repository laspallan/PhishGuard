"""Models (M): SQLAlchemy database tables only. ML code lives in services/ml/.

Every table is imported here so Base.metadata (used by Alembic) knows all of them.
"""

from phishguard.models.access import AdminUser, ApiClient
from phishguard.models.base import Base
from phishguard.models.detection import ModelVersion, Scan, ScanFeatures, ScanFeedback, TiLookup
from phishguard.models.experiments import ExperimentRun, SimulationSample
from phishguard.models.simulation import Campaign, Participant, SimulationEvent, Template

__all__ = [
    "AdminUser",
    "ApiClient",
    "Base",
    "Campaign",
    "ExperimentRun",
    "ModelVersion",
    "Participant",
    "Scan",
    "ScanFeatures",
    "ScanFeedback",
    "SimulationEvent",
    "SimulationSample",
    "Template",
    "TiLookup",
]

"""VirusTotal and AlienVault OTX clients and ti_score (Phase 4). URLhaus is not a model input
(its terms forbid AI training); it is used only in the D2 blocklist baseline."""
from phishguard.services.intel.recorder import TIRecorder
from phishguard.services.intel.service import IntelService

__all__ = ["IntelService", "TIRecorder"]

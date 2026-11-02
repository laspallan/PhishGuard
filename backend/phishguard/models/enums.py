"""Allowed values for enum columns. Stored as their string value."""

from enum import StrEnum


class AdminRole(StrEnum):
    ADMIN = "admin"
    VIEWER = "viewer"


class ClientType(StrEnum):
    EXTENSION = "extension"
    GATEWAY = "gateway"


class Modality(StrEnum):
    URL = "url"
    EMAIL = "email"


class ModelKind(StrEnum):
    RANDOM_FOREST = "random_forest"
    XGBOOST = "xgboost"
    LIGHTGBM = "lightgbm"
    LSTM = "lstm"
    CNN_1D = "cnn_1d"
    DISTILBERT = "distilbert"
    SOFT_VOTING = "soft_voting"
    STACKER = "stacker"
    CASCADE = "cascade"


class ModelStatus(StrEnum):
    CANDIDATE = "candidate"
    ACTIVE = "active"
    RETIRED = "retired"
    REJECTED = "rejected"


class Decision(StrEnum):
    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"


class Label(StrEnum):
    PHISHING = "phishing"
    LEGITIMATE = "legitimate"


class FeedbackSource(StrEnum):
    EXTENSION = "extension"
    GATEWAY = "gateway"
    ADMIN = "admin"


class IndicatorType(StrEnum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    HASH = "hash"


class TiProvider(StrEnum):
    VIRUSTOTAL = "virustotal"
    OTX = "otx"
    URLHAUS = "urlhaus"


class AttackCategory(StrEnum):
    CREDENTIAL_HARVEST = "credential_harvest"
    BRAND_IMPERSONATION = "brand_impersonation"
    MALWARE = "malware"
    SPEAR = "spear"
    UNKNOWN = "unknown"


class TemplateSplit(StrEnum):
    TRAIN = "train"
    HOLDOUT = "holdout"


class CampaignStatus(StrEnum):
    DRAFT = "draft"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class EventType(StrEnum):
    SENT = "sent"
    OPENED = "opened"
    CLICKED = "clicked"
    SUBMITTED = "submitted"  # only the fact of a submission; values are never stored
    REPORTED = "reported"


class SampleUsage(StrEnum):
    TRAIN = "train"
    SIM_HOLDOUT = "sim_holdout"


class Experiment(StrEnum):
    RQ1 = "rq1"
    RQ2 = "rq2"
    RQ3 = "rq3"


class EvalSet(StrEnum):
    DEV_CV = "dev_cv"
    FRESH_FEED = "fresh_feed"
    SIM_HOLDOUT = "sim_holdout"
    LOCKED_TEST = "locked_test"
    RECENT_EMAIL = "recent_email"

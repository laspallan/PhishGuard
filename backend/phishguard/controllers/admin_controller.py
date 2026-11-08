"""Admin controller: what the dashboard reads. Nothing here can change data."""

import json
from statistics import median
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from phishguard.core.config import Settings, get_settings
from phishguard.models import Campaign, ExperimentRun, Scan, SimulationEvent, Template
from phishguard.services.features.extractor import FEATURE_NAMES
from phishguard.services.inference.model_loader import ModelLoader
from phishguard.services.inference.service import BLOCK, WARN

LATENCY_WINDOW = 10_000


class AdminController:
    def status(self, settings: Settings | None = None) -> dict:
        settings = settings or get_settings()
        loader = ModelLoader()
        loader.load_registry()
        return {
            "status": "ok",
            "features_count": len(FEATURE_NAMES),
            "models_loaded": loader.loaded,
            "warn_threshold": WARN,
            "block_threshold": BLOCK,
            "threat_intel_configured": bool(
                settings.virustotal_api_key or settings.alienvault_otx_api_key
            ),
            "simulations_allowed": bool(settings.ethics_approval_ref),
        }

    def overview(self, session: Session) -> dict:
        def counts(column) -> dict[str, int]:
            rows = session.execute(select(column, func.count()).group_by(column)).all()
            return {str(getattr(key, "value", key)): count for key, count in rows}

        by_decision = counts(Scan.decision)
        latencies = sorted(
            session.scalars(
                select(Scan.latency_ms)
                .where(Scan.latency_ms.is_not(None))
                .order_by(Scan.created_at.desc())
                .limit(LATENCY_WINDOW)
            ).all()
        )
        return {
            "total_scans": sum(by_decision.values()),
            "by_decision": {d: by_decision.get(d, 0) for d in ("block", "warn", "allow")},
            "by_modality": counts(Scan.sample_type),
            "median_latency_ms": float(median(latencies)) if latencies else None,
            "p95_latency_ms": float(latencies[int(len(latencies) * 0.95)]) if latencies else None,
        }

    def recent_scans(self, session: Session, limit: int) -> list[dict]:
        scans = session.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit)).all()
        return [
            {
                "created_at": s.created_at,
                "sample_type": s.sample_type.value,
                "target": s.url or s.sender_domain,
                "decision": s.decision.value,
                "score": s.score,
                "latency_ms": s.latency_ms,
            }
            for s in scans
        ]

    def campaigns(self, session: Session) -> list[dict]:
        out = []
        rows = session.execute(
            select(Campaign, Template)
            .join(Template, Campaign.template_id == Template.id)
            .order_by(Campaign.created_at.desc())
        ).all()
        for campaign, template in rows:
            events = session.execute(
                select(
                    SimulationEvent.event_type,
                    func.count(SimulationEvent.participant_id.distinct()),
                )
                .where(SimulationEvent.campaign_id == campaign.id)
                .group_by(SimulationEvent.event_type)
            ).all()
            out.append(
                {
                    "name": campaign.name,
                    "status": campaign.status.value,
                    "fictional_org": template.fictional_org,
                    "template_split": template.split.value,
                    "participants_by_event": {kind.value: n for kind, n in events},
                }
            )
        return out

    def results(self, settings: Settings | None = None) -> dict[str, Any]:
        """Development results (`phishguard_ml report`); {} until a report exists."""
        path = (settings or get_settings()).data_dir / "models" / "results.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def experiments(self, session: Session) -> list[dict]:
        runs = session.scalars(
            select(ExperimentRun).order_by(ExperimentRun.round, ExperimentRun.seed)
        ).all()
        return [
            {
                "experiment": r.experiment.value,
                "round": r.round,
                "seed": r.seed,
                "arm": r.arm,
                "eval_set": r.eval_set.value,
                "k": r.k,
                "metrics": r.metrics,
            }
            for r in runs
        ]

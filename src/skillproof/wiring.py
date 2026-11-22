"""Opening SkillProof's stores: the one place that knows which store lives where. The API, the CLI and the workers
all use it, so they always see the same catalogue, approvals, history, jobs, alerts and fleet."""
from __future__ import annotations

from pathlib import Path

from skillproof.storage.approvals import ApprovalStore
from skillproof.storage.artifacts import ArtifactStore
from skillproof.authorization import GovernanceAccess
from skillproof.storage.fleet import FleetStore
from skillproof.storage.history import EvaluationHistoryStore
from skillproof.storage.jobs import JobStore
from skillproof.storage.notify import NotificationStore
from skillproof.storage.registry import SkillRegistry


def open_governance(*, database_url: str = "", data_dir: str | Path = "") -> GovernanceAccess | None:
    """PostgreSQL when a database URL is given (one database, tenant row-level security), else SQLite files in the data
    folder. None when neither is given."""
    if database_url:
        return GovernanceAccess(registry=SkillRegistry(database_url), approvals=ApprovalStore(database_url),
                                history=EvaluationHistoryStore(database_url), jobs=JobStore(database_url),
                                notifications=NotificationStore(database_url), fleet=FleetStore(database_url),
                                artifacts=ArtifactStore(database_url))
    if not data_dir:
        return None
    root = Path(data_dir)
    return GovernanceAccess(registry=SkillRegistry(root / "registry.db"), approvals=ApprovalStore(root / "approvals.db"),
                            history=EvaluationHistoryStore(root / "history.db"), jobs=JobStore(root / "jobs.db"),
                            notifications=NotificationStore(root / "notify.db"), fleet=FleetStore(root / "fleet.db"),
                            artifacts=ArtifactStore(root / "artifacts.db"))


def close_governance(governance: GovernanceAccess) -> None:
    for store in (governance.registry, governance.approvals, governance.history, governance.jobs, governance.notifications, governance.fleet, governance.artifacts):
        if store is not None:
            store.close()

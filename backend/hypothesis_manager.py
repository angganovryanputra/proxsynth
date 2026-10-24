"""
Proxsynth - Agent Working Memory & Hypothesis Ledger
Provides persistent structured memory and hypothesis tracking for autonomous security agents.
Prevents context window amnesia, eliminates duplicate probing, and maintains an active
attack agenda across multi-agent handoffs and long-running pentest campaigns.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from backend.database import SessionLocal, TestingHypothesis, Project


VALID_STATUSES = ["PLANNED", "TESTING", "CONFIRMED", "DISPROVEN", "BLOCKED"]


def create_hypothesis(
    project: str,
    target: str,
    vuln_type: str,
    hypothesis: str,
    status: str = "PLANNED",
    evidence_notes: str = "",
    agent_id: str = "primary_agent",
    linked_log_id: Optional[int] = None
) -> Dict[str, Any]:
    """Records a new attack hypothesis in the agent working memory."""
    proj_name = (project or "default").strip().lower()
    stat_clean = status.upper().strip()
    if stat_clean not in VALID_STATUSES:
        stat_clean = "PLANNED"

    db = SessionLocal()
    try:
        # Ensure project exists
        if not db.query(Project).filter(Project.name == proj_name).first():
            db.add(Project(name=proj_name, description="Auto-created workspace"))
            db.commit()

        entry = TestingHypothesis(
            project=proj_name,
            agent_id=agent_id or "primary_agent",
            target=target.strip(),
            vuln_type=(vuln_type or "GENERAL").upper().strip(),
            hypothesis=hypothesis.strip(),
            status=stat_clean,
            evidence_notes=evidence_notes.strip() if evidence_notes else "",
            linked_log_id=linked_log_id,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry.to_dict()
    finally:
        db.close()


def list_hypotheses(
    project: str = "default",
    status: Optional[str] = None,
    target: Optional[str] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Lists registered hypotheses for a project with optional status filtering."""
    proj_name = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        q = db.query(TestingHypothesis)
        if proj_name != "all":
            q = q.filter(TestingHypothesis.project == proj_name)
        if status and status.upper().strip() != "ALL":
            q = q.filter(TestingHypothesis.status == status.upper().strip())
        if target:
            q = q.filter(TestingHypothesis.target.ilike(f"%{target.strip()}%"))

        entries = q.order_by(TestingHypothesis.id.desc()).limit(limit).all()
        return [e.to_dict() for e in entries]
    finally:
        db.close()


def update_hypothesis(
    hypothesis_id: int,
    status: Optional[str] = None,
    evidence_notes: Optional[str] = None,
    project: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Updates status or findings evidence for a recorded hypothesis."""
    db = SessionLocal()
    try:
        q = db.query(TestingHypothesis).filter(TestingHypothesis.id == int(hypothesis_id))
        if project and project.strip().lower() != "all":
            q = q.filter(TestingHypothesis.project == project.strip().lower())
        
        entry = q.first()
        if not entry:
            return None

        if status:
            stat_clean = status.upper().strip()
            if stat_clean in VALID_STATUSES:
                entry.status = stat_clean
        if evidence_notes is not None:
            entry.evidence_notes = evidence_notes.strip()

        entry.updated_at = datetime.now()
        db.commit()
        db.refresh(entry)
        return entry.to_dict()
    finally:
        db.close()


def delete_hypothesis(hypothesis_id: int, project: Optional[str] = None) -> bool:
    """Removes a hypothesis from the working memory."""
    db = SessionLocal()
    try:
        q = db.query(TestingHypothesis).filter(TestingHypothesis.id == int(hypothesis_id))
        if project and project.strip().lower() != "all":
            q = q.filter(TestingHypothesis.project == project.strip().lower())
        deleted = q.delete(synchronize_session=False)
        db.commit()
        return deleted > 0
    finally:
        db.close()


def get_testing_agenda(project: str = "default") -> Dict[str, Any]:
    """
    Returns an actionable to-do agenda of pending and in-progress hypotheses.
    Allows LLM agents to instantly know what attack surfaces still need probing.
    """
    all_hyp = list_hypotheses(project=project, limit=500)
    
    planned = [h for h in all_hyp if h["status"] == "PLANNED"]
    testing = [h for h in all_hyp if h["status"] == "TESTING"]
    confirmed = [h for h in all_hyp if h["status"] == "CONFIRMED"]
    disproven = [h for h in all_hyp if h["status"] == "DISPROVEN"]
    blocked = [h for h in all_hyp if h["status"] == "BLOCKED"]

    return {
        "project": project,
        "total_hypotheses": len(all_hyp),
        "planned_count": len(planned),
        "in_progress_count": len(testing),
        "confirmed_count": len(confirmed),
        "disproven_count": len(disproven),
        "blocked_count": len(blocked),
        "active_agenda": testing + planned,
        "confirmed_findings": confirmed
    }


def sync_finding_to_hypothesis(
    project: str,
    finding_id: Optional[int],
    log_id: int,
    title: str,
    severity: str = "HIGH",
    category: str = "General",
    evidence: str = "",
    agent_id: str = "primary_agent"
) -> Dict[str, Any]:
    """
    Automatically links or elevates a TestingHypothesis in the working memory agenda
    when a vulnerability finding is confirmed and reported.
    Guarantees that get_testing_agenda() immediately reflects confirmed findings.
    """
    proj_name = (project or "default").strip().lower()
    db = SessionLocal()
    try:
        # 1. Look for existing hypothesis linked to this exact log_id
        entry = db.query(TestingHypothesis).filter(
            TestingHypothesis.linked_log_id == log_id
        ).first()

        # 2. If not found, look up HTTP Log details to locate target URL
        from backend.database import HttpLog
        log_entry = db.query(HttpLog).filter(HttpLog.id == log_id).first()
        target_str = log_entry.url if log_entry else f"Log #{log_id}"

        if not entry and log_entry:
            entry = db.query(TestingHypothesis).filter(
                TestingHypothesis.project == proj_name,
                TestingHypothesis.target == target_str,
                TestingHypothesis.vuln_type == (category or "GENERAL").upper().strip()
            ).first()

        evidence_summary = f"[Finding #{finding_id or 'rec'} | {severity}] {title}: {evidence[:200] if evidence else 'Confirmed'}"

        if entry:
            entry.status = "CONFIRMED"
            entry.evidence_notes = f"{entry.evidence_notes}\n{evidence_summary}".strip()
            entry.updated_at = datetime.now()
            if not entry.linked_log_id:
                entry.linked_log_id = log_id
            db.commit()
            db.refresh(entry)
            return entry.to_dict()
        else:
            # Auto-create confirmed hypothesis so agenda reflects the discovery
            new_entry = TestingHypothesis(
                project=proj_name,
                agent_id=agent_id or (log_entry.agent_id if log_entry else "primary_agent"),
                target=target_str,
                vuln_type=(category or "GENERAL").upper().strip(),
                hypothesis=f"Confirmed exploitability: {title}",
                status="CONFIRMED",
                evidence_notes=evidence_summary,
                linked_log_id=log_id,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            db.add(new_entry)
            db.commit()
            db.refresh(new_entry)
            return new_entry.to_dict()
    finally:
        db.close()


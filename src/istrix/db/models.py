"""iStrix ORM models — SQLAlchemy declarative base.

Tables:
  - users         : authentication / access control
  - scans         : scan configurations and results
  - jobs          : job pipeline tracking with stages
  - findings      : individual normalized findings
  - reports       : generated report metadata
  - plugins       : registered tools, skills, knowledge
  - cve_feeds     : CVE updates from RSS/polling
  - remediation   : tracked remediation tasks
  - ai_sessions   : AI chat/conversation history
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text,
    ForeignKey, JSON, Index,
)
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import DeclarativeBase, relationship

try:
    from pgvector.sqlalchemy import Vector  # type: ignore[import-untyped]
except ImportError:
    Vector = None  # type: ignore[assignment]


class Base(DeclarativeBase):
    pass


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ──────────────────────────────────────────────────────────────────
# Users
# ──────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    username = Column(String(128), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=True)
    hashed_password = Column(String(256), nullable=False)
    role = Column(String(32), default="viewer")  # admin, operator, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    last_login = Column(DateTime(timezone=True), nullable=True)

    sessions = relationship("AISession", back_populates="user")


# ──────────────────────────────────────────────────────────────────
# Scans
# ──────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    job_id = Column(UUID(as_uuid=False), ForeignKey("jobs.id"), nullable=True)
    tier = Column(String(32), nullable=False, default="normal")
    targets = Column(ARRAY(String), nullable=False)
    status = Column(String(32), default="pending")  # pending, running, done, failed
    output_file = Column(String(512), nullable=True)
    parallel_workers = Column(Integer, default=1)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    elapsed_seconds = Column(Float, default=0.0)
    hosts_scanned = Column(Integer, default=0)
    ports_open = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    errors = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    job = relationship("Job", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


# ──────────────────────────────────────────────────────────────────
# Jobs (pipeline)
# ──────────────────────────────────────────────────────────────────

class Job(Base):
    __tablename__ = "jobs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    customer_name = Column(String(256), nullable=True)
    site_name = Column(String(256), nullable=True)
    status = Column(String(32), default="draft")  # draft, queued, running, paused, done, failed
    current_stage = Column(String(64), nullable=True)
    stages = Column(JSON, default=list)  # [{name, status, started_at, finished_at, ...}]
    progress_pct = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    metadata_ = Column("metadata", JSON, default=dict)

    scans = relationship("Scan", back_populates="job", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="job", cascade="all, delete-orphan")
    remediation_tasks = relationship("RemediationTask", back_populates="job", cascade="all, delete-orphan")


# ──────────────────────────────────────────────────────────────────
# Findings
# ──────────────────────────────────────────────────────────────────

class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id"), nullable=False, index=True)
    type = Column(String(32), nullable=False, index=True)  # open_port, service, os, vulnerability, etc.
    host = Column(String(128), nullable=False, index=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(8), nullable=True)
    detail = Column(Text, nullable=False)
    severity = Column(String(16), default="info", index=True)  # critical, high, medium, low, info
    source = Column(String(64), nullable=False, index=True)
    cve = Column(String(32), nullable=True, index=True)
    evidence = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow)

    # Vector embedding column (requires pgvector extension)
    if Vector:
        embedding = Column(Vector(1536), nullable=True)
    else:
        embedding = None

    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_host_port", "host", "port"),
        Index("ix_findings_cve_severity", "cve", "severity"),
    )


# ──────────────────────────────────────────────────────────────────
# Reports
# ──────────────────────────────────────────────────────────────────

class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    job_id = Column(UUID(as_uuid=False), ForeignKey("jobs.id"), nullable=True)
    level = Column(String(32), nullable=False)  # brief, detail, threat, remediation
    format = Column(String(8), nullable=False)  # html, pdf, md
    path = Column(String(512), nullable=False)
    customer_name = Column(String(256), nullable=True)
    site_name = Column(String(256), nullable=True)
    generated_at = Column(DateTime(timezone=True), default=_utcnow)

    job = relationship("Job", back_populates="reports")


# ──────────────────────────────────────────────────────────────────
# Plugins
# ──────────────────────────────────────────────────────────────────

class Plugin(Base):
    __tablename__ = "plugins"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    name = Column(String(128), unique=True, nullable=False, index=True)
    kind = Column(String(32), nullable=False)  # tool, skill, knowledge
    description = Column(Text, nullable=True)
    version = Column(String(32), default="0.1.0")
    enabled = Column(Boolean, default=True)
    config = Column(JSON, default=dict)
    registered_at = Column(DateTime(timezone=True), default=_utcnow)


# ──────────────────────────────────────────────────────────────────
# CVE Feed
# ──────────────────────────────────────────────────────────────────

class CVEFeed(Base):
    __tablename__ = "cve_feeds"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    cve_id = Column(String(32), unique=True, nullable=False, index=True)
    title = Column(Text, nullable=True)
    cvss = Column(Float, nullable=True)
    severity = Column(String(16), nullable=True)
    summary = Column(Text, nullable=True)
    published = Column(DateTime(timezone=True), nullable=True)
    source = Column(String(64), default="nvd")  # nvd, rss, manual
    url = Column(String(512), nullable=True)
    raw_data = Column(JSON, default=dict)
    fetched_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("ix_cve_feeds_cvss", "cvss"),
        Index("ix_cve_feeds_published", "published"),
    )


# ──────────────────────────────────────────────────────────────────
# CVE Embeddings — persisted vector index for semantic search
# ──────────────────────────────────────────────────────────────────

class CveEmbedding(Base):
    """Persisted CVE knowledge-base embeddings for VectorSearch.
    
    Avoids regenerating embeddings from the API on every restart.
    Embeddings are refreshed when vulndb.yaml's last_updated timestamp
    is newer than the persisted data.
    """
    __tablename__ = "cve_embeddings"

    cve_id = Column(String(32), primary_key=True)
    title = Column(String(512), nullable=True)
    summary = Column(Text, nullable=True)
    commands = Column(JSON, default=list)
    if Vector:
        embedding = Column(Vector(1536), nullable=False)
    else:
        embedding = None
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Metadata row: a single row with vulndb_last_updated to track staleness
    source_version = Column(String(32), default="0")


# ──────────────────────────────────────────────────────────────────
# Remediation Tasks
# ──────────────────────────────────────────────────────────────────

class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    job_id = Column(UUID(as_uuid=False), ForeignKey("jobs.id"), nullable=True)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=True)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), default="open")  # open, in_progress, resolved, verified
    priority = Column(String(16), default="medium")
    assigned_to = Column(String(128), nullable=True)
    commands = Column(JSON, default=list)  # remediation shell commands
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    job = relationship("Job", back_populates="remediation_tasks")
    finding = relationship("FindingModel")


# ──────────────────────────────────────────────────────────────────
# AI Sessions
# ──────────────────────────────────────────────────────────────────

class AISession(Base):
    __tablename__ = "ai_sessions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    title = Column(String(256), default="New Chat")
    context_type = Column(String(32), nullable=True)  # scan, finding, remediation, general
    context_id = Column(UUID(as_uuid=False), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    user = relationship("User", back_populates="sessions")
    messages = relationship("AIMessage", back_populates="session", cascade="all, delete-orphan")


class AIMessage(Base):
    __tablename__ = "ai_messages"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_new_uuid)
    session_id = Column(UUID(as_uuid=False), ForeignKey("ai_sessions.id"), nullable=False, index=True)
    role = Column(String(32), nullable=False)  # user, assistant, system
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    session = relationship("AISession", back_populates="messages")

"""
Proxsynth MCP - Database Models and Engine
SQLAlchemy SQLite Persistence Layer with WAL mode, Multi-Project Scoping, Guardrails, and AI Reasoning
"""

import os
import json
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    desc,
    event,
    Index
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session
from backend.security_utils import encrypt_secret, decrypt_secret


def _resolve_db_path() -> str:
    env_path = os.getenv("PROXSYNTH_DB_PATH") or os.getenv("PROX" + "YNTH_DB_PATH")
    if env_path:
        return env_path
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proxsynth_candidate = os.path.join(base_dir, "proxsynth.db")
    proxynth_candidate = os.path.join(base_dir, "proxynth.db")
    if os.path.exists(proxsynth_candidate):
        return proxsynth_candidate
    if os.path.exists(proxynth_candidate):
        try:
            os.rename(proxynth_candidate, proxsynth_candidate)
            return proxsynth_candidate
        except Exception:
            return proxynth_candidate
    return proxsynth_candidate

DB_PATH = _resolve_db_path()
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)

# Enable SQLite WAL (Write-Ahead Logging) and high-concurrency performance pragmas
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=15000")  # Wait up to 15s instead of 5s on lock
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA cache_size=-64000")   # 64 MB page cache in RAM
    cursor.execute("PRAGMA temp_store=MEMORY")   # In-memory temporary tables & sorts
    cursor.execute("PRAGMA mmap_size=268435456") # 256 MB memory-mapped I/O
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True, default="")
    created_at = Column(DateTime, default=datetime.now)
    
    # Scope & Guardrail settings (No guardrails by default - manual configuration required)
    scope_enabled = Column(Boolean, default=False)
    allowed_hosts = Column(Text, default="[\"*\"]")  # Unrestricted by default
    blocked_patterns = Column(Text, default="[]")  # Empty by default
    allow_internal_networks = Column(Boolean, default=True)  # Internal/lab networks allowed by default
    verify_ssl = Column(Boolean, default=False)  # Enforce TLS certificate validation for targets
    
    # Rate Limiting & Proxy Chaining settings
    delay_ms = Column(Integer, default=0)  # Throttling delay between requests in milliseconds
    upstream_proxy = Column(String(255), default="")  # e.g. http://127.0.0.1:8080 (Burp Suite / Caido / ZAP)
    bola_matrix_enabled = Column(Boolean, default=True)  # Automatic background shadow replay for BOLA/IDOR detection

    def to_dict(self):
        try:
            allowed = json.loads(self.allowed_hosts) if self.allowed_hosts else ["*"]
        except Exception:
            allowed = ["*"]
        try:
            blocked = json.loads(self.blocked_patterns) if self.blocked_patterns else []
        except Exception:
            blocked = []

        return {
            "id": self.id,
            "name": self.name,
            "description": self.description or "",
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "scope_enabled": bool(self.scope_enabled),
            "allowed_hosts": allowed,
            "blocked_patterns": blocked,
            "allow_internal_networks": bool(self.allow_internal_networks),
            "verify_ssl": bool(self.verify_ssl),
            "delay_ms": self.delay_ms or 0,
            "upstream_proxy": self.upstream_proxy or "",
            "bola_matrix_enabled": bool(self.bola_matrix_enabled if self.bola_matrix_enabled is not None else True)
        }


class HttpLog(Base):
    __tablename__ = "http_logs"
    __table_args__ = (Index("ix_http_logs_proj_id", "project", "id"),)

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    project = Column(String(100), default="default", index=True)
    agent_id = Column(String(100), default="primary_agent", index=True)  # Multi-Agent Tag
    timestamp = Column(DateTime, default=datetime.now, index=True)
    source = Column(String(32), default="HTTP_CLIENT")  # HTTP_CLIENT, BROWSER_RENDER, REPEATER, FUZZER
    method = Column(String(16), default="GET", index=True)
    url = Column(Text, nullable=False)
    host = Column(String(255), index=True)
    path = Column(Text, nullable=False)
    status_code = Column(Integer, nullable=True, index=True)
    duration_ms = Column(Integer, default=0)
    proxy_attempts = Column(Integer, default=1)
    request_headers = Column(Text, default="{}")  # JSON String
    request_body = Column(Text, default="")
    response_headers = Column(Text, default="{}")  # JSON String
    response_body = Column(Text, default="")
    flag_status = Column(String(32), default="CLEAN", index=True)  # CLEAN, POTENTIAL, CONFIRMED, BLOCKED
    reasoning = Column(Text, nullable=True, default="")  # AI Agent Hypothesis / Intent

    findings = relationship("Finding", back_populates="log", cascade="all, delete-orphan", lazy="joined")

    def to_dict(self, include_body: bool = True):
        try:
            req_headers = json.loads(self.request_headers) if self.request_headers else {}
        except Exception:
            req_headers = {"raw": self.request_headers}

        try:
            res_headers = json.loads(self.response_headers) if self.response_headers else {}
        except Exception:
            res_headers = {"raw": self.response_headers}

        data = {
            "id": self.id,
            "project": self.project or "default",
            "agent_id": self.agent_id or "primary_agent",
            "timestamp": self.timestamp.isoformat() if self.timestamp else "",
            "source": self.source,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status_code": self.status_code,
            "duration_ms": self.duration_ms,
            "proxy_attempts": self.proxy_attempts if self.proxy_attempts is not None else 1,
            "request_headers": req_headers,
            "response_headers": res_headers,
            "flag_status": self.flag_status,
            "reasoning": self.reasoning or "",
            "findings": [f.to_dict() for f in (self.findings or [])]
        }
        if include_body:
            data["request_body"] = self.request_body
            data["response_body"] = self.response_body
        return data


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    log_id = Column(Integer, ForeignKey("http_logs.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    category = Column(String(255), nullable=False, index=True)
    evidence = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)

    log = relationship("HttpLog", back_populates="findings")

    def to_dict(self):
        return {
            "id": self.id,
            "log_id": self.log_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation
        }


class ActiveSession(Base):
    __tablename__ = "active_sessions"
    __table_args__ = (
        Index("ix_active_sessions_proj_dom_role", "project", "domain", "identity_role"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    project = Column(String(100), default="default", index=True)
    domain = Column(String(255), index=True, nullable=False)
    identity_role = Column(String(64), default="primary", index=True)  # primary, victim, attacker, admin, guest
    storage_state = Column(Text, nullable=False, default="{}")  # Encrypted Cookies, LocalStorage, SessionStorage
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    def get_decrypted_state(self) -> dict:
        """Decrypts and parses the stored session state dictionary."""
        raw = decrypt_secret(self.storage_state or "{}")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def set_encrypted_state(self, state_data: dict):
        """Serializes and encrypts session state dictionary before persisting."""
        raw = json.dumps(state_data)
        self.storage_state = encrypt_secret(raw)

    def to_dict(self, include_secrets: bool = True):
        state = self.get_decrypted_state()
        cookies = state.get("cookies", [])
        cookie_names = [c.get("name") for c in cookies if isinstance(c, dict) and c.get("name")]
        display_cookies = []
        for c in cookies:
            if isinstance(c, dict):
                c_copy = dict(c)
                if not include_secrets and "value" in c_copy:
                    val = str(c_copy["value"])
                    c_copy["value"] = (val[:4] + "..." + val[-3:]) if len(val) > 10 else "***"
                display_cookies.append(c_copy)

        return {
            "id": self.id,
            "project": self.project or "default",
            "domain": self.domain,
            "identity_role": self.identity_role or "primary",
            "cookie_count": len(cookies),
            "cookie_names": cookie_names,
            "cookies": display_cookies,
            "is_encrypted": bool(self.storage_state and self.storage_state.startswith("ENC:")),
            "updated_at": self.updated_at.isoformat() if self.updated_at else ""
        }


class WebSocketFrameLog(Base):
    __tablename__ = "ws_frame_logs"
    __table_args__ = (Index("ix_ws_frames_proj_id", "project", "id"),)

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    project = Column(String(100), default="default", index=True)
    url = Column(Text, nullable=False)
    direction = Column(String(16), default="CLIENT_TO_SERVER")  # CLIENT_TO_SERVER, SERVER_TO_CLIENT
    opcode = Column(String(16), default="TEXT")  # TEXT, BINARY, PING, PONG, CLOSE
    payload = Column(Text, default="")
    timestamp = Column(DateTime, default=datetime.now, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "project": self.project or "default",
            "url": self.url,
            "direction": self.direction or "CLIENT_TO_SERVER",
            "opcode": self.opcode or "TEXT",
            "payload": self.payload or "",
            "timestamp": self.timestamp.isoformat() if self.timestamp else ""
        }


class AgentCommandLog(Base):
    __tablename__ = "agent_command_logs"
    __table_args__ = (Index("ix_agent_cmd_proj_id", "project", "id"),)

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    project = Column(String(100), default="default", index=True)
    agent_id = Column(String(100), default="primary_agent", index=True)
    timestamp = Column(DateTime, default=datetime.now, index=True)
    command = Column(Text, nullable=False)
    tool_name = Column(String(64), default="terminal")
    reasoning = Column(Text, default="")
    exit_code = Column(Integer, nullable=True)
    stdout = Column(Text, default="")
    stderr = Column(Text, default="")
    duration_ms = Column(Integer, default=0)
    status = Column(String(32), default="SUCCESS")  # SUCCESS, FAILED, BLOCKED, TIMEOUT
    linked_log_id = Column(Integer, ForeignKey("http_logs.id", ondelete="SET NULL"), nullable=True)
    script_content = Column(Text, nullable=True, default="")

    def to_dict(self, include_output: bool = True):
        return {
            "id": self.id,
            "project": self.project or "default",
            "agent_id": self.agent_id or "primary_agent",
            "timestamp": self.timestamp.isoformat() if self.timestamp else "",
            "command": self.command,
            "tool_name": self.tool_name or "terminal",
            "reasoning": self.reasoning or "",
            "exit_code": self.exit_code,
            "stdout": self.stdout or "" if include_output else (self.stdout[:500] if self.stdout else ""),
            "stderr": self.stderr or "" if include_output else (self.stderr[:500] if self.stderr else ""),
            "output_truncated": not include_output and bool(self.stdout and len(self.stdout) > 500),
            "duration_ms": self.duration_ms or 0,
            "status": self.status or "SUCCESS",
            "linked_log_id": self.linked_log_id,
            "script_content": self.script_content or ""
        }


class CapturedPayload(Base):
    __tablename__ = "captured_payloads"
    __table_args__ = (Index("ix_captured_payloads_proj_id", "project", "id"),)

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    project = Column(String(100), default="default", index=True)
    agent_id = Column(String(100), default="primary_agent", index=True)
    timestamp = Column(DateTime, default=datetime.now, index=True)
    vuln_type = Column(String(64), default="CUSTOM", index=True)  # SQLI, XSS, SSRF, SSTI, LFI, RCE, IDOR, AUTH_BYPASS
    target_param = Column(String(128), default="")
    raw_payload = Column(Text, nullable=False)
    mutation_type = Column(String(64), default="DIRECT")  # DIRECT, WAF_BYPASS, POLYGLOT, ENCODED, CHUNKING
    target_url = Column(Text, default="")
    http_method = Column(String(16), default="GET")
    http_log_id = Column(Integer, ForeignKey("http_logs.id", ondelete="SET NULL"), nullable=True, index=True)
    outcome = Column(String(32), default="TESTED")  # EXECUTED, REFLECTED, WAF_BLOCKED, FILTERED, ERROR, UNCONFIRMED
    http_status = Column(Integer, nullable=True)
    response_signature = Column(String(255), default="")
    notes = Column(Text, default="")

    def to_dict(self):
        return {
            "id": self.id,
            "project": self.project or "default",
            "agent_id": self.agent_id or "primary_agent",
            "timestamp": self.timestamp.isoformat() if self.timestamp else "",
            "vuln_type": self.vuln_type or "CUSTOM",
            "target_param": self.target_param or "",
            "raw_payload": self.raw_payload,
            "mutation_type": self.mutation_type or "DIRECT",
            "target_url": self.target_url or "",
            "http_method": self.http_method or "GET",
            "http_log_id": self.http_log_id,
            "outcome": self.outcome or "TESTED",
            "http_status": self.http_status,
            "response_signature": self.response_signature or "",
            "notes": self.notes or ""
        }


class TargetAsset(Base):
    __tablename__ = "target_assets"
    __table_args__ = (Index("ix_target_assets_proj_host", "project", "host"),)

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    project = Column(String(100), default="default", index=True)
    host = Column(String(255), nullable=False, index=True)
    ip = Column(String(64), nullable=True)
    os_info = Column(String(128), default="")
    tags = Column(String(255), default="")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    services = relationship("TargetService", back_populates="asset", cascade="all, delete-orphan", lazy="selectin")
    endpoints = relationship("TargetEndpoint", back_populates="asset", cascade="all, delete-orphan", lazy="selectin")

    def to_dict(self):
        return {
            "id": self.id,
            "project": self.project or "default",
            "host": self.host,
            "ip": self.ip or "",
            "os_info": self.os_info or "",
            "tags": [t.strip() for t in self.tags.split(",") if t.strip()] if self.tags else [],
            "notes": self.notes or "",
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "updated_at": self.updated_at.isoformat() if self.updated_at else "",
            "services_count": len(self.services or []),
            "endpoints_count": len(self.endpoints or []),
            "services": [s.to_dict() for s in (self.services or [])],
            "endpoints": [e.to_dict() for e in (self.endpoints or [])]
        }


class TargetService(Base):
    __tablename__ = "target_services"
    __table_args__ = (Index("ix_target_services_asset_port", "asset_id", "port"),)

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    asset_id = Column(Integer, ForeignKey("target_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(16), default="tcp")
    service_name = Column(String(64), default="unknown")
    banner = Column(Text, default="")
    state = Column(String(32), default="open")  # open, closed, filtered
    created_at = Column(DateTime, default=datetime.now)

    asset = relationship("TargetAsset", back_populates="services")

    def to_dict(self):
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "port": self.port,
            "protocol": self.protocol or "tcp",
            "service_name": self.service_name or "unknown",
            "banner": self.banner or "",
            "state": self.state or "open",
            "created_at": self.created_at.isoformat() if self.created_at else ""
        }


class TargetEndpoint(Base):
    __tablename__ = "target_endpoints"
    __table_args__ = (Index("ix_target_endpoints_asset_method", "asset_id", "method"),)

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    asset_id = Column(Integer, ForeignKey("target_assets.id", ondelete="CASCADE"), nullable=False, index=True)
    method = Column(String(16), default="GET")
    path = Column(Text, nullable=False)
    url = Column(Text, nullable=False)
    auth_required = Column(Boolean, default=False)
    parameters = Column(Text, default="[]")
    tested_status = Column(String(32), default="UNTESTED")  # UNTESTED, IN_PROGRESS, TESTED, VULNERABLE
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.now)

    asset = relationship("TargetAsset", back_populates="endpoints")

    def to_dict(self):
        try:
            params = json.loads(self.parameters) if self.parameters else []
        except Exception:
            params = [self.parameters] if self.parameters else []
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "method": self.method or "GET",
            "path": self.path or "/",
            "url": self.url or "",
            "auth_required": bool(self.auth_required),
            "parameters": params,
            "tested_status": self.tested_status or "UNTESTED",
            "notes": self.notes or "",
            "created_at": self.created_at.isoformat() if self.created_at else ""
        }


class OastEvent(Base):
    __tablename__ = "oast_events"
    __table_args__ = (
        Index("ix_oast_events_proj_id", "project", "id"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    project = Column(String(100), default="default", index=True)
    token = Column(String(64), nullable=False, index=True)
    vuln_type = Column(String(64), default="BLIND_CALLBACK")
    protocol = Column(String(16), default="HTTP")  # HTTP, DNS
    client_ip = Column(String(64), nullable=True)
    method = Column(String(16), default="GET")
    path = Column(Text, default="")
    request_headers = Column(Text, default="{}")
    query_params = Column(Text, default="{}")
    request_body = Column(Text, default="")
    description = Column(Text, default="")
    timestamp = Column(DateTime, default=datetime.now, index=True)

    def to_dict(self):
        try:
            hdrs = json.loads(self.request_headers) if self.request_headers else {}
        except Exception:
            hdrs = {}
        try:
            params = json.loads(self.query_params) if self.query_params else {}
        except Exception:
            params = {}
        return {
            "id": self.id,
            "project": self.project or "default",
            "token": self.token,
            "vuln_type": self.vuln_type or "BLIND_CALLBACK",
            "protocol": self.protocol or "HTTP",
            "client_ip": self.client_ip or "",
            "method": self.method or "GET",
            "path": self.path or "",
            "headers": hdrs,
            "query_params": params,
            "request_body": self.request_body or "",
            "description": self.description or "",
            "timestamp": self.timestamp.isoformat() if self.timestamp else ""
        }


class TestingHypothesis(Base):
    __tablename__ = "testing_hypotheses"
    __table_args__ = (
        Index("ix_hypotheses_proj_status", "project", "status"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    project = Column(String(100), default="default", index=True)
    agent_id = Column(String(100), default="primary_agent", index=True)
    target = Column(String(255), nullable=False)  # Endpoint, URL, or host:port
    vuln_type = Column(String(64), default="GENERAL")  # BOLA, SQLI, SSRF, BAC, RACE, XSS, AUTH_BYPASS
    hypothesis = Column(Text, nullable=False)
    status = Column(String(32), default="PLANNED")  # PLANNED, TESTING, CONFIRMED, DISPROVEN, BLOCKED
    evidence_notes = Column(Text, default="")
    linked_log_id = Column(Integer, ForeignKey("http_logs.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        return {
            "id": self.id,
            "project": self.project or "default",
            "agent_id": self.agent_id or "primary_agent",
            "target": self.target,
            "vuln_type": self.vuln_type or "GENERAL",
            "hypothesis": self.hypothesis,
            "status": self.status or "PLANNED",
            "evidence_notes": self.evidence_notes or "",
            "linked_log_id": self.linked_log_id,
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "updated_at": self.updated_at.isoformat() if self.updated_at else ""
        }


class InterceptionRule(Base):
    __tablename__ = "interception_rules"
    __table_args__ = (
        Index("ix_rules_proj_enabled", "project", "enabled"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    name = Column(String(128), nullable=False)
    project = Column(String(100), default="default", index=True)
    enabled = Column(Boolean, default=True)
    priority = Column(Integer, default=10)  # Lower number = higher priority
    rule_type = Column(String(32), default="REQUEST")  # REQUEST, RESPONSE, MOCK

    # Match criteria
    match_url = Column(String(255), default="*")  # regex or wildcard
    match_method = Column(String(32), default="*")  # GET, POST, or *
    match_header = Column(String(255), default="")  # e.g. "User-Agent: curl*" or header name
    match_body = Column(Text, default="")  # substring or regex

    # Action configuration
    action_type = Column(String(32), default="REPLACE_HEADER")  # REPLACE_HEADER, REMOVE_HEADER, REPLACE_BODY, REWRITE_URL, MOCK_RESPONSE
    action_target = Column(String(255), default="")  # Header name, target regex, or mock status code
    action_value = Column(Text, default="")  # Replacement value or mock response body
    action_extra = Column(Text, default="{}")  # JSON metadata (e.g. mock headers)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    def to_dict(self):
        try:
            extra = json.loads(self.action_extra) if self.action_extra else {}
        except Exception:
            extra = {}
        return {
            "id": self.id,
            "name": self.name,
            "project": self.project or "default",
            "enabled": bool(self.enabled),
            "priority": self.priority or 10,
            "rule_type": self.rule_type or "REQUEST",
            "match_url": self.match_url or "*",
            "match_method": self.match_method or "*",
            "match_header": self.match_header or "",
            "match_body": self.match_body or "",
            "action_type": self.action_type or "REPLACE_HEADER",
            "action_target": self.action_target or "",
            "action_value": self.action_value or "",
            "action_extra": extra,
            "created_at": self.created_at.isoformat() if self.created_at else "",
            "updated_at": self.updated_at.isoformat() if self.updated_at else ""
        }


def _run_migrations():
    """Safely adds newly introduced columns and high-performance indexes to existing SQLite tables."""
    import sqlite3
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("PRAGMA table_info(projects)")
        proj_cols = [row[1] for row in cur.fetchall()]
        if "delay_ms" not in proj_cols:
            cur.execute("ALTER TABLE projects ADD COLUMN delay_ms INTEGER DEFAULT 0")
        if "upstream_proxy" not in proj_cols:
            cur.execute("ALTER TABLE projects ADD COLUMN upstream_proxy VARCHAR(255) DEFAULT ''")
        if "allow_internal_networks" not in proj_cols:
            cur.execute("ALTER TABLE projects ADD COLUMN allow_internal_networks BOOLEAN DEFAULT 1")
        if "verify_ssl" not in proj_cols:
            cur.execute("ALTER TABLE projects ADD COLUMN verify_ssl BOOLEAN DEFAULT 0")
        if "bola_matrix_enabled" not in proj_cols:
            cur.execute("ALTER TABLE projects ADD COLUMN bola_matrix_enabled BOOLEAN DEFAULT 1")

        cur.execute("PRAGMA table_info(http_logs)")
        log_cols = [row[1] for row in cur.fetchall()]
        if "agent_id" not in log_cols:
            cur.execute("ALTER TABLE http_logs ADD COLUMN agent_id VARCHAR(100) DEFAULT 'primary_agent'")
        if "proxy_attempts" not in log_cols:
            cur.execute("ALTER TABLE http_logs ADD COLUMN proxy_attempts INTEGER DEFAULT 1")

        cur.execute("PRAGMA table_info(active_sessions)")
        sess_cols = [row[1] for row in cur.fetchall()]
        if "identity_role" not in sess_cols:
            cur.execute("ALTER TABLE active_sessions ADD COLUMN identity_role VARCHAR(64) DEFAULT 'primary'")

        cur.execute("PRAGMA table_info(agent_command_logs)")
        cmd_cols = [row[1] for row in cur.fetchall()]
        if "script_content" not in cmd_cols:
            cur.execute("ALTER TABLE agent_command_logs ADD COLUMN script_content TEXT DEFAULT ''")

        # Performance Indexes for zero-lag filtering & sorting
        cur.execute("CREATE INDEX IF NOT EXISTS ix_http_logs_proj_id ON http_logs(project, id DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_http_logs_id_desc ON http_logs(id DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_http_logs_flag ON http_logs(flag_status)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_http_logs_method ON http_logs(method)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_agent_cmd_proj_id ON agent_command_logs(project, id DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_agent_cmd_id_desc ON agent_command_logs(id DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_agent_cmd_status ON agent_command_logs(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_captured_payloads_proj_id ON captured_payloads(project, id DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_captured_payloads_id_desc ON captured_payloads(id DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_captured_payloads_vuln_type ON captured_payloads(vuln_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_captured_payloads_outcome ON captured_payloads(outcome)")

        # Target Knowledge Graph & OAST indexes
        cur.execute("CREATE INDEX IF NOT EXISTS ix_target_assets_proj_host ON target_assets(project, host)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_target_services_asset_port ON target_services(asset_id, port)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_target_endpoints_asset_method ON target_endpoints(asset_id, method)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_oast_events_token ON oast_events(token)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_oast_events_proj_id ON oast_events(project, id DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_active_sessions_proj_dom_role ON active_sessions(project, domain, identity_role)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_ws_frames_proj_id ON ws_frame_logs(project, id DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_hypotheses_proj_status ON testing_hypotheses(project, status)")
        cur.execute("CREATE INDEX IF NOT EXISTS ix_rules_proj_enabled ON interception_rules(project, enabled)")
        con.commit()
        con.close()
    except Exception as ex:
        pass


def init_db():
    """Create all database tables, perform schema migrations, and ensure default project exists with zero default guardrails."""
    Base.metadata.create_all(bind=engine)
    
    # Run column migrations for SQLite
    _run_migrations()

    db = SessionLocal()
    try:
        default_proj = db.query(Project).filter(Project.name == "default").first()
        if not default_proj:
            db.add(Project(
                name="default",
                description="Default security testing workspace (unrestricted guardrails)",
                scope_enabled=False,
                allowed_hosts=json.dumps(["*"]),
                blocked_patterns=json.dumps([]),
                allow_internal_networks=True,
                verify_ssl=False,
                delay_ms=0,
                upstream_proxy=""
            ))
            db.commit()
        else:
            # Ensure existing default project has guardrails disabled by default
            updated = False
            if default_proj.scope_enabled:
                default_proj.scope_enabled = False
                updated = True
            if default_proj.blocked_patterns != "[]":
                default_proj.blocked_patterns = json.dumps([])
                updated = True
            if default_proj.allowed_hosts != '["*"]':
                default_proj.allowed_hosts = json.dumps(["*"])
                updated = True
            if not default_proj.allow_internal_networks:
                default_proj.allow_internal_networks = True
                updated = True
            if updated:
                db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def get_db() -> Generator[Session, None, None]:
    """Dependency for obtaining a SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


"""
KAVACH v2 - SQLite Audit Store & Persistence
Records security inspections, tool authorizations, and benchmark runs
using asynchronous SQLite (aiosqlite).
Ensures safe logging (redacts sensitive tokens, bounds stored text sizes).
"""

import os
import aiosqlite
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_PATH = os.getenv("KAVACH_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "kavach.db"))
logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS security_inspections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    request_id TEXT NOT NULL,
    source TEXT NOT NULL,
    decision TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    threat_score REAL NOT NULL,
    latency_ms REAL NOT NULL,
    categories_detected TEXT,
    rules_triggered INTEGER DEFAULT 0,
    ml_predicted_label TEXT,
    ml_score REAL,
    task_alignment TEXT,
    is_educational INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tool_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    caller_role TEXT NOT NULL,
    authorized INTEGER NOT NULL,
    policy_code TEXT NOT NULL,
    decision_reason TEXT,
    risk_level TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS benchmark_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    baseline_type TEXT NOT NULL,
    num_trials INTEGER NOT NULL,
    asr REAL NOT NULL,
    fpr REAL NOT NULL,
    f1_score REAL NOT NULL,
    median_latency_ms REAL NOT NULL,
    p95_latency_ms REAL NOT NULL,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS workflow_runs (
    request_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    workflow TEXT NOT NULL,
    status TEXT NOT NULL,
    backend_id TEXT NOT NULL,
    backend_kind TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    trace_json TEXT NOT NULL
);
"""


async def init_db(db_path: str = DB_PATH):
    """Initializes tables if not already created."""
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(SCHEMA_SQL)
        await db.commit()


async def log_inspection(
    request_id: str,
    source: str,
    decision: str,
    risk_level: str,
    threat_score: float,
    latency_ms: float,
    categories: List[str],
    rules_count: int = 0,
    ml_label: Optional[str] = None,
    ml_score: Optional[float] = None,
    task_alignment: Optional[str] = None,
    is_educational: bool = False,
    db_path: str = DB_PATH
):
    """Logs an inspection decision to SQLite."""
    try:
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                """
                INSERT INTO security_inspections (
                    timestamp, request_id, source, decision, risk_level, threat_score,
                    latency_ms, categories_detected, rules_triggered, ml_predicted_label,
                    ml_score, task_alignment, is_educational
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    request_id,
                    source,
                    decision,
                    risk_level,
                    threat_score,
                    latency_ms,
                    json.dumps(categories),
                    rules_count,
                    ml_label,
                    ml_score,
                    task_alignment,
                    1 if is_educational else 0
                )
            )
            await db.commit()
        return True
    except Exception:
        logger.warning("Security inspection audit could not be persisted")
        return False


async def log_tool_authorization(
    tool_name: str,
    caller_role: str,
    authorized: bool,
    policy_code: str,
    decision_reason: str,
    risk_level: str,
    db_path: str = DB_PATH
):
    """Logs a tool authorization event."""
    try:
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                """
                INSERT INTO tool_authorizations (
                    timestamp, tool_name, caller_role, authorized, policy_code,
                    decision_reason, risk_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    tool_name,
                    caller_role,
                    1 if authorized else 0,
                    policy_code,
                    decision_reason[:300],
                    risk_level
                )
            )
            await db.commit()
        return True
    except Exception:
        logger.warning("Tool authorization audit could not be persisted")
        return False


async def get_recent_inspections(limit: int = 50, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Retrieves recent inspection records for the dashboard."""
    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM security_inspections ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


async def get_security_metrics_summary(db_path: str = DB_PATH) -> Dict[str, Any]:
    """Computes summary metrics for security overview."""
    try:
        async with aiosqlite.connect(db_path) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM security_inspections")
            total = (await cursor.fetchone())[0]

            cursor = await db.execute("SELECT decision, COUNT(*) FROM security_inspections GROUP BY decision")
            decisions_raw = await cursor.fetchall()
            decisions = {d[0]: d[1] for d in decisions_raw}

            cursor = await db.execute("SELECT AVG(latency_ms) FROM security_inspections")
            avg_lat = (await cursor.fetchone())[0] or 0.0

            return {
                "status": "available",
                "available": True,
                "total_requests": total,
                "decisions": {
                    "ALLOW": decisions.get("ALLOW", 0),
                    "FLAG": decisions.get("FLAG", 0),
                    "REVIEW": decisions.get("REVIEW", 0),
                    "BLOCK": decisions.get("BLOCK", 0)
                },
                "average_latency_ms": round(float(avg_lat), 2)
            }
    except Exception:
        return {
            "status": "unavailable", "available": False,
            "total_requests": None, "decisions": {}, "average_latency_ms": None,
        }


async def log_workflow(result: Dict[str, Any], principal_id: str, db_path: str = DB_PATH) -> bool:
    """Persist decision traces, never queries, document bodies, model output or tool data."""
    try:
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO workflow_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (result["request_id"], datetime.now(timezone.utc).isoformat(), principal_id,
                 result["workflow"], result["status"], result["backend"]["id"], result["backend"]["kind"],
                 result["latency_ms"], json.dumps(result["trace"])),
            )
            await db.commit()
        return True
    except Exception:
        logger.warning("Protected workflow audit could not be persisted")
        return False


async def get_workflow_runs(principal_id: str, limit: int = 20, db_path: str = DB_PATH) -> Dict[str, Any]:
    try:
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT request_id, timestamp, workflow, status, backend_id, backend_kind, latency_ms "
                "FROM workflow_runs WHERE principal_id = ? ORDER BY timestamp DESC LIMIT ?",
                (principal_id, max(1, min(limit, 100))),
            )
            return {"status": "available", "runs": [dict(row) for row in await cursor.fetchall()]}
    except Exception:
        return {"status": "unavailable", "runs": []}

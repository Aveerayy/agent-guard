"""PostgreSQL persistence layer for audit events, token records, and gateway calls.

Provides ``PgAuditLog`` and ``PgTokenInventory`` that implement the same
public interface as the in-memory versions so they can be used as drop-in
replacements in ``MCPGateway`` and ``DashboardState``.

Falls back to in-memory storage when asyncpg is unavailable or no database
URL is configured, so the server can start without PostgreSQL for development.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from agent_guard.audit.logger import AuditEvent, AuditLog
from agent_guard.tokens.inventory import (
    TokenInventory,
    TokenRecord,
)

logger = logging.getLogger(__name__)

SQL_CREATE_TABLES = """\
CREATE TABLE IF NOT EXISTS audit_events (
    id              SERIAL PRIMARY KEY,
    team_id         TEXT NOT NULL DEFAULT '',
    event_id        TEXT NOT NULL,
    timestamp       DOUBLE PRECISION NOT NULL,
    event_type      TEXT NOT NULL DEFAULT 'policy_decision',
    agent_id        TEXT NOT NULL DEFAULT '',
    action          TEXT NOT NULL DEFAULT '',
    allowed         BOOLEAN NOT NULL DEFAULT FALSE,
    effect          TEXT NOT NULL DEFAULT '',
    matched_rule    TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT '',
    parameters_json TEXT NOT NULL DEFAULT '{}',
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    hash            TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS token_records (
    id              SERIAL PRIMARY KEY,
    team_id         TEXT NOT NULL DEFAULT '',
    token_id        TEXT NOT NULL,
    provider        TEXT NOT NULL DEFAULT 'unknown',
    token_type      TEXT NOT NULL DEFAULT 'unknown',
    masked_value    TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT 'env_var',
    source_detail   TEXT NOT NULL DEFAULT '',
    risk_score      INTEGER NOT NULL DEFAULT 0,
    risk_level      TEXT NOT NULL DEFAULT 'low',
    status          TEXT NOT NULL DEFAULT 'active',
    first_seen      DOUBLE PRECISION NOT NULL,
    last_used       DOUBLE PRECISION NOT NULL,
    use_count       INTEGER NOT NULL DEFAULT 1,
    agents_json     TEXT NOT NULL DEFAULT '[]',
    tools_json      TEXT NOT NULL DEFAULT '[]',
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    UNIQUE(team_id, token_id)
);

CREATE TABLE IF NOT EXISTS gateway_calls (
    id              SERIAL PRIMARY KEY,
    team_id         TEXT NOT NULL DEFAULT '',
    tool_name       TEXT NOT NULL,
    agent_id        TEXT NOT NULL DEFAULT '',
    allowed         BOOLEAN NOT NULL DEFAULT FALSE,
    reason          TEXT NOT NULL DEFAULT '',
    timestamp       DOUBLE PRECISION NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_team ON audit_events(team_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_tokens_team ON token_records(team_id);
CREATE INDEX IF NOT EXISTS idx_calls_team ON gateway_calls(team_id);
"""


class PgAuditLog(AuditLog):
    """AuditLog backed by PostgreSQL.

    Keeps the in-memory chain for hash verification while persisting
    every event to the database for cross-process queries.
    """

    def __init__(
        self,
        *,
        pool: Any = None,
        team_id: str = "",
    ) -> None:
        super().__init__()
        self._pool = pool
        self._team_id = team_id

    def log(
        self,
        event_type: str = "policy_decision",
        *,
        agent_id: str = "",
        action: str = "",
        allowed: bool = False,
        effect: str = "",
        matched_rule: str = "",
        reason: str = "",
        parameters: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        event = super().log(
            event_type,
            agent_id=agent_id,
            action=action,
            allowed=allowed,
            effect=effect,
            matched_rule=matched_rule,
            reason=reason,
            parameters=parameters,
            metadata=metadata,
        )
        if self._pool is not None:
            self._persist_event(event)
        return event

    def _persist_event(self, event: AuditEvent) -> None:
        """Best-effort async persistence (fire-and-forget from sync context)."""
        import asyncio

        async def _insert() -> None:
            try:
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        """INSERT INTO audit_events
                           (team_id, event_id, timestamp, event_type, agent_id,
                            action, allowed, effect, matched_rule, reason,
                            parameters_json, metadata_json, hash)
                           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
                        self._team_id,
                        event.event_id,
                        event.timestamp,
                        event.event_type,
                        event.agent_id,
                        event.action,
                        event.allowed,
                        event.effect,
                        event.matched_rule,
                        event.reason,
                        json.dumps(event.parameters, default=str),
                        json.dumps(event.metadata, default=str),
                        event.hash,
                    )
            except Exception:
                logger.warning("Failed to persist audit event %s", event.event_id, exc_info=True)

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_insert())
        except RuntimeError:
            pass


class PgTokenInventory(TokenInventory):
    """TokenInventory backed by PostgreSQL.

    Keeps in-memory state for fast reads while persisting changes
    to the database for org-wide aggregation.
    """

    def __init__(self, *, pool: Any = None, team_id: str = "") -> None:
        super().__init__()
        self._pool = pool
        self._team_id = team_id

    def register(self, record: TokenRecord) -> TokenRecord:
        result = super().register(record)
        if self._pool is not None:
            self._persist_token(result)
        return result

    def _persist_token(self, record: TokenRecord) -> None:
        import asyncio

        async def _upsert() -> None:
            try:
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        """INSERT INTO token_records
                           (team_id, token_id, provider, token_type, masked_value,
                            source, source_detail, risk_score, risk_level, status,
                            first_seen, last_used, use_count,
                            agents_json, tools_json, metadata_json)
                           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
                           ON CONFLICT (team_id, token_id) DO UPDATE SET
                            last_used = EXCLUDED.last_used,
                            use_count = EXCLUDED.use_count,
                            risk_score = EXCLUDED.risk_score,
                            risk_level = EXCLUDED.risk_level,
                            agents_json = EXCLUDED.agents_json,
                            tools_json = EXCLUDED.tools_json""",
                        self._team_id,
                        record.token_id,
                        record.provider.value,
                        record.token_type.value,
                        record.masked_value,
                        record.source.value,
                        record.source_detail,
                        record.risk_score,
                        record.risk_level.value,
                        record.status.value,
                        record.first_seen,
                        record.last_used,
                        record.use_count,
                        json.dumps(record.agents),
                        json.dumps(record.tools),
                        json.dumps(record.metadata, default=str),
                    )
            except Exception:
                logger.warning("Failed to persist token %s", record.token_id, exc_info=True)

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_upsert())
        except RuntimeError:
            pass


async def init_db(pool: Any) -> None:
    """Create tables if they don't exist."""
    async with pool.acquire() as conn:
        await conn.execute(SQL_CREATE_TABLES)


async def query_audit_events(
    pool: Any,
    *,
    team_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Query audit events from the database (for the dashboard API)."""
    async with pool.acquire() as conn:
        if team_id:
            rows = await conn.fetch(
                "SELECT * FROM audit_events WHERE team_id=$1 ORDER BY timestamp DESC LIMIT $2",
                team_id,
                limit,
            )
        else:
            rows = await conn.fetch(
                "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT $1",
                limit,
            )
        return [dict(r) for r in rows]


async def query_token_records(
    pool: Any,
    *,
    team_id: str | None = None,
) -> list[dict[str, Any]]:
    """Query token records from the database."""
    async with pool.acquire() as conn:
        if team_id:
            rows = await conn.fetch(
                "SELECT * FROM token_records WHERE team_id=$1 ORDER BY risk_score DESC",
                team_id,
            )
        else:
            rows = await conn.fetch("SELECT * FROM token_records ORDER BY risk_score DESC")
        return [dict(r) for r in rows]


async def query_gateway_stats(
    pool: Any,
    *,
    team_id: str | None = None,
) -> dict[str, Any]:
    """Aggregate gateway call stats."""
    async with pool.acquire() as conn:
        where = "WHERE team_id=$1" if team_id else ""
        args: list[Any] = [team_id] if team_id else []

        total = await conn.fetchval(f"SELECT COUNT(*) FROM gateway_calls {where}", *args)
        cond = "AND" if where else "WHERE"
        allowed = await conn.fetchval(
            f"SELECT COUNT(*) FROM gateway_calls {where} {cond} allowed=TRUE",
            *args,
        )
        teams_count = await conn.fetchval("SELECT COUNT(DISTINCT team_id) FROM gateway_calls")

        return {
            "total_calls": total or 0,
            "allowed": allowed or 0,
            "denied": (total or 0) - (allowed or 0),
            "teams_active": teams_count or 0,
        }


async def insert_gateway_call(
    pool: Any,
    *,
    team_id: str,
    tool_name: str,
    agent_id: str,
    allowed: bool,
    reason: str,
) -> None:
    """Record a gateway call to the database."""
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO gateway_calls
                   (team_id, tool_name, agent_id, allowed, reason, timestamp)
                   VALUES ($1, $2, $3, $4, $5, $6)""",
                team_id,
                tool_name,
                agent_id,
                allowed,
                reason,
                time.time(),
            )
    except Exception:
        logger.warning("Failed to persist gateway call", exc_info=True)

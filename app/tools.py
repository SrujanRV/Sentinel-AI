"""Tool registry, policy validation layer, and external service providers."""

import ipaddress
import json
import logging
import re
import sqlite3
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from app.config import Settings
from app.schemas import Severity

logger = logging.getLogger("sentinel.tools")

MAX_TOOL_CALLS = 3
REGISTERED_TOOLS = {"ip_reputation", "create_ticket"}


# ── Tool Argument Schemas ────────────────────────────────────────────────────


class IPReputationArgs(BaseModel):
    """Arguments for the ip_reputation tool."""

    ip: str = Field(..., description="Public IPv4 or IPv6 address to check.")


class CreateTicketArgs(BaseModel):
    """Arguments for the create_ticket tool."""

    title: str = Field(..., description="Short title describing the incident.")
    severity: Severity = Field(
        ..., description="Incident severity level (high or critical)."
    )
    summary: str = Field(..., description="Summary of incident and evidence.")


# ── OpenAI Function Definitions ──────────────────────────────────────────────

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ip_reputation",
            "description": (
                "Query threat reputation and abuse reports for an observed "
                "external IP address."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": (
                            "Public IPv4 or IPv6 address observed in the alert events."
                        ),
                    }
                },
                "required": ["ip"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_ticket",
            "description": (
                "Create an incident response ticket in the SOC database "
                "for high or critical threats."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Concise incident ticket title.",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["high", "critical"],
                        "description": (
                            "Alert severity. Allowed only for high or critical."
                        ),
                    },
                    "summary": {
                        "type": "string",
                        "description": "Incident summary and key evidence.",
                    },
                },
                "required": ["title", "severity", "summary"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    },
]


# ── Provider Interfaces & Implementations ────────────────────────────────────


class IPReputationProvider(ABC):
    """Interface for IP threat intelligence lookup."""

    @abstractmethod
    async def check_ip(self, ip: str) -> dict[str, Any]:
        """Look up reputation and abuse report count for *ip*."""


class MockIPReputationProvider(IPReputationProvider):
    """Deterministic in-memory mock provider for testing and offline operation."""

    async def check_ip(self, ip: str) -> dict[str, Any]:
        # Return deterministic score based on IP characteristics
        is_suspicious = ip.endswith((".50", ".100", ".200", ".66"))
        return {
            "ip": ip,
            "abuse_confidence_score": 85 if is_suspicious else 0,
            "is_known_attacker": is_suspicious,
            "country_code": "US",
            "total_reports": 14 if is_suspicious else 0,
            "provider": "MockIPReputation",
        }


class AbuseIPDBProvider(IPReputationProvider):
    """AbuseIPDB v2 API provider."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._base_url = "https://api.abuseipdb.com/api/v2/check"

    async def check_ip(self, ip: str) -> dict[str, Any]:
        import httpx

        headers = {"Key": self._api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(self._base_url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "ip": data.get("ipAddress", ip),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "is_known_attacker": data.get("abuseConfidenceScore", 0) > 20,
                "country_code": data.get("countryCode", "UNKNOWN"),
                "total_reports": data.get("totalReports", 0),
                "provider": "AbuseIPDB",
            }


class TicketStore(ABC):
    """Interface for incident ticket persistence."""

    @abstractmethod
    async def create_ticket(
        self, title: str, severity: str, summary: str
    ) -> dict[str, Any]:
        """Persist a new incident ticket and return its metadata."""


class SQLiteTicketStore(TicketStore):
    """Local SQLite-backed ticket store."""

    def __init__(self, db_path: str = "tickets.db") -> None:
        self._db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    async def create_ticket(
        self, title: str, severity: str, summary: str
    ) -> dict[str, Any]:
        created_at = datetime.now(UTC).isoformat()
        with sqlite3.connect(self._db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO tickets (title, severity, summary, created_at) "
                "VALUES (?, ?, ?, ?)",
                (title, severity, summary, created_at),
            )
            conn.commit()
            ticket_id = cursor.lastrowid

        return {
            "ticket_id": ticket_id,
            "title": title,
            "severity": severity,
            "created_at": created_at,
            "status": "created",
        }


# ── Policy & Execution Layer ─────────────────────────────────────────────────


class ToolPolicy:
    """Enforces allow-lists, argument validity, injection guards, and call limits."""

    def __init__(
        self,
        allowed_ips: set[str],
        injection_flagged: bool,
        max_calls: int = MAX_TOOL_CALLS,
    ) -> None:
        self.allowed_ips = allowed_ips
        self.injection_flagged = injection_flagged
        self.max_calls = max_calls
        self.call_count = 0

    def check_call_limit(self) -> str | None:
        """Check if call limit has been reached."""
        if self.call_count >= self.max_calls:
            return (
                f"Call cap reached (maximum {self.max_calls} tool calls per analysis)."
            )
        return None

    def validate_tool_name(self, name: str) -> str | None:
        """Check if tool is in the registered allow-list."""
        if name not in REGISTERED_TOOLS:
            return f"Tool '{name}' is not in the allow-list."
        return None

    def validate_ip(self, ip_str: str) -> str | None:
        """Validate that IP is public, valid, and observed in the input events."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return f"Invalid IP address format: '{ip_str}'."

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_link_local
        ):
            return (
                f"IP address '{ip_str}' is private, loopback, or reserved. "
                "Reputation queries are permitted only for public routable IPs."
            )

        clean_ip = ip_str.strip()
        if str(ip_obj) not in self.allowed_ips and clean_ip not in self.allowed_ips:
            return (
                f"IP address '{ip_str}' was not observed in the sanitized input events."
            )

        return None

    def validate_ticket_creation(self, severity: Severity) -> str | None:
        """Check severity rubric and prompt injection status before creating ticket."""
        if self.injection_flagged:
            return (
                "Ticket creation denied: prompt injection attempt was detected "
                "in input logs."
            )

        if severity not in (Severity.high, Severity.critical):
            return (
                f"Tickets may only be created for high or critical alerts. "
                f"Requested severity: '{severity.value}'."
            )

        return None


class ToolExecutor:
    """Executes registered tools through the allow-list policy layer."""

    def __init__(
        self,
        policy: ToolPolicy,
        ip_provider: IPReputationProvider,
        ticket_store: TicketStore,
    ) -> None:
        self.policy = policy
        self.ip_provider = ip_provider
        self.ticket_store = ticket_store

    async def execute(
        self, name: str, raw_args: dict[str, Any] | str
    ) -> dict[str, Any]:
        """Validate and execute a tool request, recording the action."""
        # 1. Parse arguments if passed as JSON string
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError as exc:
                return {
                    "tool": name,
                    "args": {"raw": raw_args},
                    "status": "denied",
                    "denial_reason": f"Malformed JSON arguments: {exc}",
                }
        else:
            args = raw_args

        # 2. Enforce call cap
        limit_err = self.policy.check_call_limit()
        if limit_err:
            logger.warning("Tool call denied by policy: %s", limit_err)
            return {
                "tool": name,
                "args": args,
                "status": "denied",
                "denial_reason": limit_err,
            }

        # Count this call attempt against the cap
        self.policy.call_count += 1

        # 3. Validate tool name allow-list
        name_err = self.policy.validate_tool_name(name)
        if name_err:
            logger.warning("Unknown tool attempted: %s", name)
            return {
                "tool": name,
                "args": args,
                "status": "denied",
                "denial_reason": name_err,
            }

        # 4. Route and execute tool with specific policies
        if name == "ip_reputation":
            try:
                parsed_ip_args = IPReputationArgs(**args)
            except ValidationError as exc:
                return {
                    "tool": name,
                    "args": args,
                    "status": "denied",
                    "denial_reason": f"Invalid arguments for ip_reputation: {exc}",
                }

            ip_err = self.policy.validate_ip(parsed_ip_args.ip)
            if ip_err:
                logger.info("ip_reputation denied: %s", ip_err)
                return {
                    "tool": name,
                    "args": args,
                    "status": "denied",
                    "denial_reason": ip_err,
                }

            result = await self.ip_provider.check_ip(parsed_ip_args.ip)
            return {
                "tool": name,
                "args": args,
                "status": "executed",
                "result": result,
            }

        if name == "create_ticket":
            try:
                parsed_ticket_args = CreateTicketArgs(**args)
            except ValidationError as exc:
                return {
                    "tool": name,
                    "args": args,
                    "status": "denied",
                    "denial_reason": f"Invalid arguments for create_ticket: {exc}",
                }

            ticket_err = self.policy.validate_ticket_creation(
                parsed_ticket_args.severity
            )
            if ticket_err:
                logger.warning("create_ticket denied: %s", ticket_err)
                return {
                    "tool": name,
                    "args": args,
                    "status": "denied",
                    "denial_reason": ticket_err,
                }

            result = await self.ticket_store.create_ticket(
                title=parsed_ticket_args.title,
                severity=parsed_ticket_args.severity.value,
                summary=parsed_ticket_args.summary,
            )
            return {
                "tool": name,
                "args": args,
                "status": "executed",
                "result": result,
            }

        return {
            "tool": name,
            "args": args,
            "status": "denied",
            "denial_reason": f"Unimplemented tool: {name}",
        }


def extract_observed_ips(events: list[Any]) -> set[str]:
    """Extract observed IPs from event.src_ip and regex matches in event.message."""
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    observed: set[str] = set()

    for event in events:
        if getattr(event, "src_ip", None):
            observed.add(str(event.src_ip).strip())
        msg = getattr(event, "message", "")
        for match in ip_pattern.findall(msg):
            try:
                ipaddress.ip_address(match)
                observed.add(match)
            except ValueError:
                continue

    return observed


def create_tool_executor(
    settings: Settings,
    allowed_ips: set[str],
    injection_flagged: bool,
    ip_provider: IPReputationProvider | None = None,
    ticket_store: TicketStore | None = None,
) -> ToolExecutor:
    """Factory creating a ToolExecutor with configured or default providers."""
    policy = ToolPolicy(
        allowed_ips=allowed_ips,
        injection_flagged=injection_flagged,
        max_calls=MAX_TOOL_CALLS,
    )

    if ip_provider is None:
        if settings.abuseipdb_api_key:
            ip_provider = AbuseIPDBProvider(api_key=settings.abuseipdb_api_key)
        else:
            ip_provider = MockIPReputationProvider()

    if ticket_store is None:
        ticket_store = SQLiteTicketStore(db_path=settings.sqlite_db_path)

    return ToolExecutor(
        policy=policy,
        ip_provider=ip_provider,
        ticket_store=ticket_store,
    )

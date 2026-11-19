"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        import time

        key = request_id or user_id
        self._open[key] = time.time()
        self._open[f"{key}__input_text"] = text  # type: ignore[assignment]
        self._open[f"{key}__ts_iso"] = utc_now_iso()  # type: ignore[assignment]

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        import time

        key = request_id or user_id
        start_time = self._open.pop(key, None)
        input_text = self._open.pop(f"{key}__input_text", "")
        ts_iso = self._open.pop(f"{key}__ts_iso", None) or utc_now_iso()
        latency_ms = (
            round((time.time() - float(start_time)) * 1000.0, 2)
            if isinstance(start_time, (int, float))
            else 0.0
        )
        entry = {
            "timestamp": ts_iso,
            "user_id": user_id,
            "request_id": request_id or user_id,
            "input": input_text,
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": latency_ms,
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

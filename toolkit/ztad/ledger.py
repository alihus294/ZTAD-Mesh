from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from .util import canonical_json, sha256_bytes, utc_now

GENESIS_HASH = "sha256:" + "0" * 64
SCHEMA_VERSION = 2


def _record_hash(record_without_hash: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(record_without_hash))


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    # journal_mode can race during the very first concurrent opens. Retry the
    # initialization pragma rather than allowing a startup-only lock to break
    # the append-only ledger.
    for attempt in range(60):
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 59:
                conn.close()
                raise
            time.sleep(min(0.005 * (attempt + 1), 0.1))
    conn.execute("PRAGMA synchronous=FULL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS ledger_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ledger_entries (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            task_id TEXT,
            idempotency_key TEXT NOT NULL UNIQUE,
            previous_hash TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS ledger_checkpoints (
            checkpoint_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            head_hash TEXT NOT NULL,
            checkpoint_json TEXT NOT NULL
        );
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO ledger_meta(key,value) VALUES('schema_version',?)",
        (str(SCHEMA_VERSION),),
    )
    return conn


def append_record(
    path: Path,
    payload: dict[str, Any],
    *,
    idempotency_key: str | None = None,
    task_id: str | None = None,
) -> dict[str, Any]:
    """Append transactionally and safely under concurrent writers.

    The caller should supply a stable idempotency key for retried external
    operations. If omitted, the payload hash is used, making exact duplicate
    appends idempotent.
    """
    if not isinstance(payload, dict):
        raise ValueError("Ledger payload must be a mapping")
    idempotency_key = idempotency_key or sha256_bytes(canonical_json(payload))
    conn = _connect(path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            "SELECT * FROM ledger_entries WHERE idempotency_key=?", (idempotency_key,)
        ).fetchone()
        if existing is not None:
            conn.execute("COMMIT")
            return _row_to_record(existing) | {"idempotent_replay": True}
        previous = conn.execute(
            "SELECT sequence,record_hash FROM ledger_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["record_hash"] if previous else GENESIS_HASH
        created_at = utc_now()
        payload_json = canonical_json(payload).decode("utf-8")
        cursor = conn.execute(
            """INSERT INTO ledger_entries(created_at,task_id,idempotency_key,previous_hash,payload_json,record_hash)
               VALUES(?,?,?,?,?,?)""",
            (created_at, task_id, idempotency_key, previous_hash, payload_json, "PENDING"),
        )
        sequence = int(cursor.lastrowid)
        unhashed = {
            "sequence": sequence,
            "created_at": created_at,
            "task_id": task_id,
            "idempotency_key": idempotency_key,
            "previous_hash": previous_hash,
            "payload": payload,
        }
        record_hash = _record_hash(unhashed)
        conn.execute(
            "UPDATE ledger_entries SET record_hash=? WHERE sequence=?", (record_hash, sequence)
        )
        conn.execute("COMMIT")
        return unhashed | {"record_hash": record_hash, "idempotent_replay": False}
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def _row_to_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "sequence": int(row["sequence"]),
        "created_at": row["created_at"],
        "task_id": row["task_id"],
        "idempotency_key": row["idempotency_key"],
        "previous_hash": row["previous_hash"],
        "payload": json.loads(row["payload_json"]),
        "record_hash": row["record_hash"],
    }


def create_checkpoint(path: Path, checkpoint_path: Path) -> dict[str, Any]:
    """Create an external head anchor used to detect later tail truncation.

    The checkpoint file must be stored in a separately protected location for
    strong tamper resistance. This function is deterministic except timestamp.
    """
    conn = _connect(path)
    try:
        row = conn.execute(
            "SELECT sequence,record_hash FROM ledger_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(row["sequence"]) if row else 0
        head_hash = row["record_hash"] if row else GENESIS_HASH
        checkpoint = {
            "schema_version": 1,
            "created_at": utc_now(),
            "ledger": str(path.resolve()),
            "sequence": sequence,
            "head_hash": head_hash,
        }
        checkpoint["checkpoint_id"] = sha256_bytes(canonical_json(checkpoint))
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint_path.write_text(json.dumps(checkpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        conn.execute(
            "INSERT OR REPLACE INTO ledger_checkpoints(checkpoint_id,created_at,sequence,head_hash,checkpoint_json) VALUES(?,?,?,?,?)",
            (
                checkpoint["checkpoint_id"], checkpoint["created_at"], sequence,
                head_hash, json.dumps(checkpoint, sort_keys=True),
            ),
        )
        return checkpoint
    finally:
        conn.close()


def verify_ledger(path: Path, *, checkpoint_path: Path | None = None) -> dict[str, Any]:
    if not path.exists():
        return {"valid": checkpoint_path is None, "records": 0, "errors": [] if checkpoint_path is None else ["Ledger missing while checkpoint was supplied"]}
    conn = _connect(path)
    errors: list[str] = []
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    count = 0
    head_hash = GENESIS_HASH
    try:
        rows = conn.execute("SELECT * FROM ledger_entries ORDER BY sequence").fetchall()
        for row in rows:
            record = _row_to_record(row)
            count += 1
            if record["sequence"] != expected_sequence:
                errors.append(f"sequence gap: expected {expected_sequence}, got {record['sequence']}")
            if record["previous_hash"] != previous_hash:
                errors.append(f"sequence {record['sequence']}: previous_hash mismatch")
            unhashed = {key: value for key, value in record.items() if key != "record_hash"}
            actual = _record_hash(unhashed)
            if record["record_hash"] != actual:
                errors.append(f"sequence {record['sequence']}: record_hash mismatch")
            previous_hash = record["record_hash"]
            head_hash = record["record_hash"]
            expected_sequence = record["sequence"] + 1
        checkpoint_result: dict[str, Any] | None = None
        if checkpoint_path is not None:
            try:
                checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                checkpoint_result = {
                    "path": str(checkpoint_path.resolve()),
                    "sequence": checkpoint.get("sequence"),
                    "head_hash": checkpoint.get("head_hash"),
                    "matches": checkpoint.get("sequence") == count and checkpoint.get("head_hash") == head_hash,
                }
                if not checkpoint_result["matches"]:
                    errors.append("Ledger head does not match the external checkpoint; truncation or divergence detected")
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"Invalid checkpoint: {exc}")
                checkpoint_result = {"path": str(checkpoint_path), "matches": False}
        else:
            checkpoint_result = None
        return {
            "valid": not errors,
            "records": count,
            "errors": errors,
            "head_hash": head_hash,
            "checkpoint": checkpoint_result,
            "claim_boundary": "Tail deletion is detectable only when a separately protected checkpoint is supplied.",
        }
    finally:
        conn.close()

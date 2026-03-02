from __future__ import annotations

import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple


SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_epoch INTEGER NOT NULL,
  severity TEXT NOT NULL,
  label TEXT NOT NULL,
  src_ip TEXT,
  dst_ip TEXT,
  src_port INTEGER,
  dst_port INTEGER,
  proto TEXT,
  score REAL,
  corr_reason TEXT,
  encrypted_payload BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_det_ts ON detections(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_det_src ON detections(src_ip);
CREATE INDEX IF NOT EXISTS idx_det_dst ON detections(dst_ip);
"""


class Database:
    def __init__(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def insert_detection(
        self,
        severity: str,
        label: str,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        proto: Optional[str],
        score: Optional[float],
        corr_reason: str,
        encrypted_payload: bytes,
        ts_epoch: Optional[int] = None,
    ) -> int:
        ts = int(ts_epoch or time.time())
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO detections
                  (ts_epoch, severity, label, src_ip, dst_ip, src_port, dst_port, proto, score, corr_reason, encrypted_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ts, severity, label, src_ip, dst_ip, src_port, dst_port, proto, score, corr_reason, encrypted_payload),
            )
            conn.commit()
            return int(cur.lastrowid)

    def list_detections(
        self,
        limit: int = 200,
        severity: Optional[str] = None,
        label: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        since_epoch: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        q = """
        SELECT id, ts_epoch, severity, label, src_ip, dst_ip, src_port, dst_port, proto, score, corr_reason
        FROM detections
        WHERE 1=1
        """
        params: List[Any] = []

        if severity:
            q += " AND severity = ?"
            params.append(severity)
        if label:
            q += " AND label = ?"
            params.append(label)
        if src_ip:
            q += " AND src_ip = ?"
            params.append(src_ip)
        if dst_ip:
            q += " AND dst_ip = ?"
            params.append(dst_ip)
        if since_epoch:
            q += " AND ts_epoch >= ?"
            params.append(int(since_epoch))

        q += " ORDER BY ts_epoch DESC, id DESC LIMIT ?"
        params.append(int(limit))

        with self._connect() as conn:
            rows = conn.execute(q, tuple(params)).fetchall()
            return [dict(r) for r in rows]

    def get_detection_payload(self, det_id: int) -> Optional[bytes]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT encrypted_payload FROM detections WHERE id = ?",
                (det_id,),
            ).fetchone()
            if not row:
                return None
            return row["encrypted_payload"]

    def stats_anomalies_per_minute(self, minutes: int = 60) -> List[Tuple[int, int]]:
        minutes = max(5, min(24 * 60, minutes))
        since = int(time.time()) - minutes * 60
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT (ts_epoch / 60) * 60 AS bucket_epoch, COUNT(*) AS cnt
                FROM detections
                WHERE ts_epoch >= ? AND label = 'anomaly'
                GROUP BY bucket_epoch
                ORDER BY bucket_epoch ASC
                """,
                (since,),
            ).fetchall()
            return [(int(r["bucket_epoch"]), int(r["cnt"])) for r in rows]

    def stats_top_sources(self, minutes: int = 60, limit: int = 10) -> List[Tuple[str, int]]:
        minutes = max(5, min(24 * 60, minutes))
        limit = max(3, min(50, limit))
        since = int(time.time()) - minutes * 60
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT src_ip, COUNT(*) AS cnt
                FROM detections
                WHERE ts_epoch >= ? AND label = 'anomaly' AND src_ip IS NOT NULL AND src_ip != ''
                GROUP BY src_ip
                ORDER BY cnt DESC
                LIMIT ?
                """,
                (since, limit),
            ).fetchall()
            return [(str(r["src_ip"]), int(r["cnt"])) for r in rows]

    def stats_top_ports(self, minutes: int = 60, limit: int = 10) -> List[Tuple[int, int]]:
        minutes = max(5, min(24 * 60, minutes))
        limit = max(3, min(50, limit))
        since = int(time.time()) - minutes * 60
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT dst_port, COUNT(*) AS cnt
                FROM detections
                WHERE ts_epoch >= ? AND label = 'anomaly' AND dst_port IS NOT NULL
                GROUP BY dst_port
                ORDER BY cnt DESC
                LIMIT ?
                """,
                (since, limit),
            ).fetchall()
            return [(int(r["dst_port"]), int(r["cnt"])) for r in rows]

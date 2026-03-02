from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Set, Tuple


@dataclass
class CorrelationEvent:
    ts: float
    src_ip: str
    dst_ip: str
    dst_port: int
    label: str
    score: float


class Correlator:
    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = window_seconds
        self.by_src: Dict[str, Deque[CorrelationEvent]] = defaultdict(deque)

    def add(self, ev: CorrelationEvent) -> Tuple[str, str, Dict[str, int]]:
        q = self.by_src[ev.src_ip]
        q.append(ev)

        cutoff = time.time() - self.window_seconds
        while q and q[0].ts < cutoff:
            q.popleft()

        unique_ports: Set[int] = {e.dst_port for e in q if e.dst_port}
        unique_hosts: Set[str] = {e.dst_ip for e in q if e.dst_ip}
        anomaly_count = sum(1 for e in q if e.label == "anomaly")

        meta = {
            "anomaly_count_in_window": anomaly_count,
            "unique_ports_in_window": len(unique_ports),
            "unique_hosts_in_window": len(unique_hosts),
            "window_seconds": self.window_seconds,
        }

        if anomaly_count >= 8 and len(unique_ports) >= 10:
            return "critical", "Scan like behavior detected via correlation", meta

        if anomaly_count >= 10 and len(unique_hosts) >= 5:
            return "high", "Suspicious spread across multiple targets", meta

        if anomaly_count >= 5:
            return "medium", "Repeated anomalies from same source", meta

        return "info", "No strong correlation", meta

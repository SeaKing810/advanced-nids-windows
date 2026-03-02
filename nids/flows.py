from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Tuple, List

FlowKey = Tuple[str, str, int, int, str]


@dataclass
class FlowStats:
    first_seen: float
    last_seen: float
    packet_count: int = 0
    byte_total: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    sizes: List[int] = field(default_factory=list)

    def add_packet(self, size: int, flags: int, is_tcp: bool) -> None:
        now = time.time()
        self.last_seen = now
        self.packet_count += 1
        self.byte_total += size
        self.sizes.append(size)

        if is_tcp:
            if flags & 0x02:
                self.syn_count += 1
            if flags & 0x10:
                self.ack_count += 1
            if flags & 0x04:
                self.rst_count += 1
            if flags & 0x01:
                self.fin_count += 1

    def to_vector(self) -> List[float]:
        duration = max(0.001, self.last_seen - self.first_seen)
        mean_size = (self.byte_total / self.packet_count) if self.packet_count else 0.0
        pps = self.packet_count / duration
        bps = self.byte_total / duration
        syn_to_ack = self.syn_count / max(1, self.ack_count)
        rst_rate = self.rst_count / max(1, self.packet_count)

        return [
            float(self.packet_count),
            float(self.byte_total),
            float(mean_size),
            float(duration),
            float(pps),
            float(bps),
            float(self.syn_count),
            float(self.ack_count),
            float(self.rst_count),
            float(self.fin_count),
            float(syn_to_ack),
            float(rst_rate),
        ]


class FlowTable:
    def __init__(self, flush_after_seconds: int = 15) -> None:
        self.flush_after_seconds = flush_after_seconds
        self.flows: Dict[FlowKey, FlowStats] = {}

    def update(self, key: FlowKey, pkt_size: int, tcp_flags: int, is_tcp: bool) -> None:
        now = time.time()
        if key not in self.flows:
            self.flows[key] = FlowStats(first_seen=now, last_seen=now)
        self.flows[key].add_packet(pkt_size, tcp_flags, is_tcp)

    def flush_ready(self) -> Dict[FlowKey, FlowStats]:
        now = time.time()
        ready: Dict[FlowKey, FlowStats] = {}
        for k, st in list(self.flows.items()):
            if now - st.last_seen >= self.flush_after_seconds:
                ready[k] = st
                del self.flows[k]
        return ready

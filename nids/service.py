from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from .alerts import AlertManager
from .correlation import Correlator, CorrelationEvent
from .crypto import Crypto
from .db import Database
from .features import packet_to_flow_update
from .flows import FlowTable
from .model import AnomalyModel
from .sniffer import PacketSniffer


class NIDSService:
    def __init__(
        self,
        sniffer: PacketSniffer,
        model: AnomalyModel,
        db: Database,
        crypto: Crypto,
        alerts: AlertManager,
        alert_cooldown_seconds: float = 30.0,
    ) -> None:
        self.sniffer = sniffer
        self.model = model
        self.db = db
        self.crypto = crypto
        self.alerts = alerts

        self.flow_table = FlowTable(flush_after_seconds=15)
        self.correlator = Correlator(window_seconds=300)

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self._last_alert_by_src: Dict[str, float] = {}
        self._alert_cooldown_seconds = float(alert_cooldown_seconds)

    def start_background(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        def handle(pkt):
            if self._stop.is_set():
                return

            key, meta = packet_to_flow_update(pkt)
            if key is None:
                return

            pkt_size = int(meta.get("ip_len", 0) or 0)
            tcp_flags = int(meta.get("tcp_flags", 0) or 0)
            is_tcp = bool(meta.get("is_tcp", False))

            self.flow_table.update(key, pkt_size=pkt_size, tcp_flags=tcp_flags, is_tcp=is_tcp)

            ready = self.flow_table.flush_ready()
            if not ready:
                return

            for flow_key, flow_stats in ready.items():
                src_ip, dst_ip, src_port, dst_port, proto = flow_key
                vector = flow_stats.to_vector()
                result = self.model.infer(vector)

                label = "anomaly" if result.is_anomaly else "normal"
                severity = "high" if result.is_anomaly else "info"

                corr_reason = "n/a"
                corr_meta: Dict[str, Any] = {}

                if result.is_anomaly and src_ip:
                    corr_event = CorrelationEvent(
                        ts=time.time(),
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=int(dst_port or 0),
                        label=label,
                        score=float(result.score),
                    )
                    corr_sev, corr_reason, corr_counts = self.correlator.add(corr_event)
                    corr_meta = {"severity": corr_sev, "reason": corr_reason, "counts": corr_counts}
                    if corr_sev in {"critical", "high", "medium"}:
                        severity = corr_sev

                payload: Dict[str, Any] = {
                    "label": label,
                    "severity": severity,
                    "score": float(result.score),
                    "flow": {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "proto": proto,
                    },
                    "flow_stats": {
                        "packet_count": flow_stats.packet_count,
                        "byte_total": flow_stats.byte_total,
                        "syn_count": flow_stats.syn_count,
                        "ack_count": flow_stats.ack_count,
                        "rst_count": flow_stats.rst_count,
                        "fin_count": flow_stats.fin_count,
                        "duration_seconds": float(flow_stats.last_seen - flow_stats.first_seen),
                    },
                    "vector": vector,
                    "correlation": corr_meta,
                    "ts_epoch": int(time.time()),
                }

                token = self.crypto.encrypt_json(payload)

                self.db.insert_detection(
                    severity=severity,
                    label=label,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(src_port or 0) if src_port else None,
                    dst_port=int(dst_port or 0) if dst_port else None,
                    proto=proto,
                    score=float(result.score),
                    corr_reason=corr_reason,
                    encrypted_payload=token,
                )

                if result.is_anomaly:
                    now = time.time()
                    last = self._last_alert_by_src.get(src_ip, 0.0)
                    if now - last < self._alert_cooldown_seconds:
                        continue
                    self._last_alert_by_src[src_ip] = now

                    title = f"NIDS alert {severity.upper()}"
                    msg = (
                        f"Score {result.score:.4f}\n"
                        f"Flow {src_ip}:{src_port} to {dst_ip}:{dst_port} {proto}\n"
                        f"Packets {flow_stats.packet_count} Bytes {flow_stats.byte_total}\n"
                        f"Correlation {corr_reason}\n"
                    )
                    self.alerts.send(title, msg)

        self.sniffer.live_sniff(on_packet=handle)

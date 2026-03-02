from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from .flows import FlowKey


def packet_to_flow_update(pkt: Packet) -> Tuple[Optional[FlowKey], Dict[str, Any]]:
    if not pkt.haslayer(IP):
        return None, {}

    ip = pkt[IP]
    src_ip = getattr(ip, "src", "")
    dst_ip = getattr(ip, "dst", "")
    ip_len = int(getattr(ip, "len", 0) or 0)
    ttl = int(getattr(ip, "ttl", 0) or 0)

    proto = "OTHER"
    src_port = 0
    dst_port = 0
    is_tcp = False
    flags_int = 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        proto = "TCP"
        is_tcp = True
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        try:
            flags_int = int(tcp.flags)
        except Exception:
            flags_int = 0
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        proto = "UDP"
        src_port = int(udp.sport)
        dst_port = int(udp.dport)

    key: FlowKey = (src_ip, dst_ip, src_port, dst_port, proto)

    meta: Dict[str, Any] = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "ip_len": ip_len,
        "ttl": ttl,
        "tcp_flags": flags_int,
        "is_tcp": is_tcp,
    }
    return key, meta

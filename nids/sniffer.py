from __future__ import annotations

import os
import time
from typing import Callable

from scapy.all import sniff, wrpcap  # type: ignore
from scapy.packet import Packet


class PacketSniffer:
    def __init__(self, interface: str, bpf_filter: str, pcap_dir: str) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.pcap_dir = pcap_dir
        os.makedirs(self.pcap_dir, exist_ok=True)

    def capture_to_pcap(self, seconds: int = 10, max_packets: int = 2000) -> str:
        ts = int(time.time())
        path = os.path.join(self.pcap_dir, f"capture_{ts}.pcap")

        pkts = sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            timeout=seconds,
            count=max_packets,
            store=True,
        )
        wrpcap(path, pkts)
        return path

    def live_sniff(self, on_packet: Callable[[Packet], None]) -> None:
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=on_packet,
            store=False,
        )

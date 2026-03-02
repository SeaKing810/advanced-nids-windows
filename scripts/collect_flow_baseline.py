from __future__ import annotations

import csv
import os
import time

from nids.config import settings
from nids.features import packet_to_flow_update
from nids.flows import FlowTable
from nids.sniffer import PacketSniffer


def main() -> None:
    os.makedirs("data", exist_ok=True)
    out_path = os.path.join("data", f"flow_baseline_{int(time.time())}.csv")

    sniffer = PacketSniffer(settings.interface, settings.bpf_filter, settings.pcap_dir)
    flows = FlowTable(flush_after_seconds=15)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "packet_count",
            "byte_total",
            "mean_size",
            "duration",
            "pps",
            "bps",
            "syn_count",
            "ack_count",
            "rst_count",
            "fin_count",
            "syn_to_ack",
            "rst_rate",
        ])

        def handle(pkt):
            key, meta = packet_to_flow_update(pkt)
            if key is None:
                return

            flows.update(
                key,
                pkt_size=int(meta.get("ip_len", 0) or 0),
                tcp_flags=int(meta.get("tcp_flags", 0) or 0),
                is_tcp=bool(meta.get("is_tcp", False)),
            )

            ready = flows.flush_ready()
            for _, st in ready.items():
                w.writerow(st.to_vector())
                f.flush()

        print("Collecting baseline flows. Press Ctrl C to stop.")
        sniffer.live_sniff(on_packet=handle)

    print(f"Saved baseline to {out_path}")


if __name__ == "__main__":
    main()

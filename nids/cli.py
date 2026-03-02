from __future__ import annotations

import argparse
import sys
import time

from .alerts import AlertManager
from .config import settings
from .crypto import Crypto
from .db import Database
from .model import AnomalyModel
from .service import NIDSService
from .sniffer import PacketSniffer


def cmd_interfaces(_: argparse.Namespace) -> int:
    from scapy.all import get_if_list  # type: ignore
    for name in get_if_list():
        print(name)
    return 0


def cmd_run(_: argparse.Namespace) -> int:
    sniffer = PacketSniffer(settings.interface, settings.bpf_filter, settings.pcap_dir)
    model = AnomalyModel(settings.model_path)
    db = Database(settings.db_path)
    crypto = Crypto(settings.log_encryption_key)

    alerts = AlertManager(
        enabled=settings.alerts_enabled,
        rate_per_min=settings.alert_rate_limit_per_min,
        twilio_enabled=settings.twilio_enabled,
        twilio_sid=settings.twilio_account_sid,
        twilio_token=settings.twilio_auth_token,
        twilio_from=settings.twilio_from_number,
        twilio_to=settings.twilio_to_number,
        smtp_enabled=settings.smtp_enabled,
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_username=settings.smtp_username,
        smtp_password=settings.smtp_password,
        smtp_from=settings.smtp_from_email,
        smtp_to=settings.smtp_to_email,
    )

    svc = NIDSService(
        sniffer=sniffer,
        model=model,
        db=db,
        crypto=crypto,
        alerts=alerts,
        alert_cooldown_seconds=settings.alert_cooldown_seconds,
    )

    svc.start_background()
    print("NIDS running. Press Ctrl C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        svc.stop()
        return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nids", description="Advanced NIDS with flow detection and correlation")
    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("interfaces", help="List capture interfaces")
    s1.set_defaults(func=cmd_interfaces)

    s2 = sub.add_parser("run", help="Run NIDS service")
    s2.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

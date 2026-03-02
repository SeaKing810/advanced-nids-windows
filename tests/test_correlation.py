import time
from nids.correlation import Correlator, CorrelationEvent


def test_correlation_escalates():
    c = Correlator(window_seconds=300)
    src = "1.1.1.1"
    for i in range(9):
        sev, reason, meta = c.add(
            CorrelationEvent(
                ts=time.time(),
                src_ip=src,
                dst_ip="2.2.2.2",
                dst_port=1000 + i,
                label="anomaly",
                score=1.0,
            )
        )
    assert sev in {"medium", "high", "critical"}
    assert "correlation" in reason or len(reason) > 0
    assert meta["anomaly_count_in_window"] >= 9

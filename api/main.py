from __future__ import annotations

import os
import time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from nids.config import settings
from nids.crypto import Crypto
from nids.db import Database

from .auth import create_token, decode_token, verify_user

app = FastAPI(title="Advanced NIDS Dashboard")

db = Database(settings.db_path)
crypto = Crypto(settings.log_encryption_key)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def require_auth(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth.replace("Bearer ", "").strip()
    try:
        data = decode_token(token)
        return data.sub
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(STATIC_DIR, "index.html"), "r", encoding="utf-8") as f:
        return f.read()


@app.post("/api/login")
async def login(payload: dict):
    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))
    if not verify_user(username, password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": create_token(username)}


@app.get("/api/detections")
def detections(
    limit: int = 200,
    severity: Optional[str] = None,
    label: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    minutes: int = 120,
    user: str = Depends(require_auth),
):
    limit = max(1, min(1000, limit))
    since = int(time.time()) - max(5, min(24 * 60, minutes)) * 60
    items = db.list_detections(
        limit=limit,
        severity=severity,
        label=label,
        src_ip=src_ip,
        dst_ip=dst_ip,
        since_epoch=since,
    )
    return {"items": items, "user": user}


@app.get("/api/detections/{det_id}")
def detection_detail(det_id: int, user: str = Depends(require_auth)):
    token = db.get_detection_payload(det_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Not found")
    payload = crypto.decrypt_json(token)
    payload["viewer"] = user
    return payload


@app.get("/api/stats")
def stats(minutes: int = 120, user: str = Depends(require_auth)):
    minutes = max(5, min(24 * 60, minutes))
    per_min = db.stats_anomalies_per_minute(minutes=minutes)
    top_src = db.stats_top_sources(minutes=minutes, limit=10)
    top_ports = db.stats_top_ports(minutes=minutes, limit=10)
    return {
        "minutes": minutes,
        "anomalies_per_minute": [{"t": t, "count": c} for t, c in per_min],
        "top_sources": [{"src_ip": s, "count": c} for s, c in top_src],
        "top_ports": [{"dst_port": p, "count": c} for p, c in top_ports],
        "user": user,
    }

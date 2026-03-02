# Advanced NIDS for Windows (Flow Based Detection + Correlation + Real Time Alerts)

This project is a local first Network Intrusion Detection System designed to look and feel like a SOC tool.

It captures network traffic, aggregates it into flows, runs ML based anomaly detection, correlates events over time like a mini SIEM, logs encrypted event payloads to SQLite, and provides an authenticated web dashboard with charts and filters.

## Core capabilities

Flow based detection
Packets are aggregated into short time window flows keyed by src ip, dst ip, src port, dst port, protocol.

Anomaly detection
An IsolationForest model is trained on baseline flows from your own network traffic.

Correlation
Events are correlated by source over a rolling window to detect scan like behavior and repeated anomalies.

Encrypted logging
Full event payloads are encrypted at rest. The SQLite table stores only a small summary plus the encrypted payload.

Real time alerts
Supports Twilio SMS and SMTP email with rate limiting and cooldown to prevent spam.

Dashboard
FastAPI backend, authenticated endpoints, live table, filters, and charts.

## Ethical use

Run only on networks you own or have explicit permission to monitor.

## Windows prerequisites

Npcap is required for Scapy sniffing on Windows.
Install Npcap and enable WinPcap compatible mode.

Run PowerShell as Administrator for packet capture.

## Setup

1) Create venv and install dependencies

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

2) Create .env

Copy .env.example to .env.

Generate LOG_ENCRYPTION_KEY

python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

3) Set your capture interface name

List interfaces

python -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))"

Set NIDS_INTERFACE in .env to your active adapter name, usually Wi-Fi or Ethernet.

## Train the live anomaly model

Collect baseline flows
Run PowerShell as Administrator

python scripts\collect_flow_baseline.py

This writes a CSV to data.

Train model

python scripts\train_live_model.py data\flow_baseline_XXXXXXXX.csv

This writes models\live_isoforest.joblib

## Run the system

Start dashboard

uvicorn api.main:app --reload --port 8000

Open
http://127.0.0.1:8000

Login uses DASH_USERNAME and DASH_PASSWORD from .env.

Start NIDS capture and detection
Run PowerShell as Administrator

python run_nids.py

## Demo ideas

The model flags behavior that differs from baseline. For an easy demo:
Open several new outbound connections quickly
Access multiple ports on a host you own in a short time window
You should see correlation severity increase and alerts consolidate per source

## Security notes

Secrets are loaded from .env and should never be committed.
Event payloads are encrypted at rest.
All dashboard endpoints require a Bearer token.
Alerts include rate limiting and cooldown.

If you extend this further, add:
Password hashing for dashboard credentials
User management and RBAC
API rate limiting middleware
Retention policy for old events

## Project mapping to SOC roles

Packet capture and traffic analysis
Flow feature engineering
Anomaly detection model training and evaluation
Event correlation and severity escalation
Alerting integration
Logging, monitoring, and dashboarding
Secure coding practices

from __future__ import annotations

import smtplib
import time
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Optional

from twilio.rest import Client


@dataclass
class RateLimiter:
    per_minute: int
    window_start: float = 0.0
    count: int = 0

    def allow(self) -> bool:
        now = time.time()
        if now - self.window_start >= 60:
            self.window_start = now
            self.count = 0
        if self.count >= self.per_minute:
            return False
        self.count += 1
        return True


class AlertManager:
    def __init__(
        self,
        enabled: bool,
        rate_per_min: int,
        twilio_enabled: bool,
        twilio_sid: str,
        twilio_token: str,
        twilio_from: str,
        twilio_to: str,
        smtp_enabled: bool,
        smtp_host: str,
        smtp_port: int,
        smtp_username: str,
        smtp_password: str,
        smtp_from: str,
        smtp_to: str,
    ) -> None:
        self.enabled = enabled
        self.limiter = RateLimiter(per_minute=rate_per_min)

        self.twilio_enabled = twilio_enabled
        self.twilio_from = twilio_from
        self.twilio_to = twilio_to
        self._twilio: Optional[Client] = None
        if twilio_enabled and twilio_sid and twilio_token:
            self._twilio = Client(twilio_sid, twilio_token)

        self.smtp_enabled = smtp_enabled
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.smtp_from = smtp_from
        self.smtp_to = smtp_to

    def send(self, title: str, message: str) -> None:
        if not self.enabled:
            return
        if not self.limiter.allow():
            return

        if self.twilio_enabled:
            self._send_twilio_sms(title, message)

        if self.smtp_enabled:
            self._send_email(title, message)

    def _send_twilio_sms(self, title: str, message: str) -> None:
        if not self._twilio:
            return
        if not (self.twilio_from and self.twilio_to):
            return
        body = f"{title}\n{message}"
        try:
            self._twilio.messages.create(body=body, from_=self.twilio_from, to=self.twilio_to)
        except Exception:
            pass

    def _send_email(self, title: str, message: str) -> None:
        if not (self.smtp_host and self.smtp_username and self.smtp_password and self.smtp_from and self.smtp_to):
            return

        msg = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = title
        msg["From"] = self.smtp_from
        msg["To"] = self.smtp_to

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.smtp_from, [self.smtp_to], msg.as_string())
        except Exception:
            pass

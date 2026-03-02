from __future__ import annotations

import json
from cryptography.fernet import Fernet, InvalidToken


class Crypto:
    def __init__(self, fernet_key: str) -> None:
        if not fernet_key:
            raise ValueError("LOG_ENCRYPTION_KEY is required. Set it in .env")
        self._fernet = Fernet(fernet_key.encode())

    def encrypt_json(self, payload: dict) -> bytes:
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return self._fernet.encrypt(raw)

    def decrypt_json(self, token: bytes) -> dict:
        try:
            raw = self._fernet.decrypt(token)
            return json.loads(raw.decode("utf-8"))
        except InvalidToken:
            return {"error": "decrypt_failed"}

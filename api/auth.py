from __future__ import annotations

import time
from dataclasses import dataclass

import jwt
from passlib.context import CryptContext

from nids.config import settings

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


@dataclass
class TokenData:
    sub: str
    exp: int


def verify_user(username: str, password: str) -> bool:
    if username != settings.dash_username:
        return False
    return password == settings.dash_password


def create_token(username: str) -> str:
    exp = int(time.time()) + settings.jwt_expire_minutes * 60
    payload = {"sub": username, "exp": exp}
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str) -> TokenData:
    data = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    return TokenData(sub=str(data["sub"]), exp=int(data["exp"]))

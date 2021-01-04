# coding=utf-8
from pydantic import BaseModel
from typing import List


class GenToken(BaseModel):
    """
    field to generate encrypt_key
    """
    token_expire: str
    allow_method: List[str]


class GrandToken(GenToken):
    jwt_algorithm: str
    user_token: str
    user_id: str
    encrypt_key: str  #: base64((secret_key + json(GenToken)).encode("utf-8"))


class Auth(BaseModel):
    #: 用户名
    user_id: str
    #: 当前Unix时间戳,单位是秒,不是毫秒
    timestamp: int


class HashAuth(Auth):
    code: str


class EncryptAuth(Auth, GenToken):
    token: str  #: encrypt(jwt(GrandToken), GrandToken.encrypt_key, sha256(Auth.timestamp)[:12])

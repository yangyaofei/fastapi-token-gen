# coding=utf-8
from pydantic import BaseModel
from typing import List


class AccessField(BaseModel):
    """
    field to generate encrypt_key
    """
    token_expire: int
    allow_method: List[str]

    def gen_salt(self):
        method = "".join(sorted(self.allow_method))
        return (str(self.token_expire) + method).lower()


class GrandToken(AccessField):
    jwt_algorithm: str
    varify_token: str  #: 用于验证, 用户将GrandToken中除 encrypy_key 之外内容发送给服务端,返回该key是否有效
    user_id: str
    encrypt_key: str  #: base64((secret_key + json(AccessField)).encode("utf-8"))


class Auth(BaseModel):
    #: 用户名
    user_id: str
    #: 当前Unix时间戳,单位是秒,不是毫秒
    timestamp: int


class HashAuth(Auth):
    code: str


class EncryptAuth(Auth, AccessField):
    # token: str  #: encrypt(jwt(GrandToken), GrandToken.encrypt_key, sha256(Auth.timestamp)[:12])
    pass

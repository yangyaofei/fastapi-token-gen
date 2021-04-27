# coding=utf-8
from typing import List

from pydantic import BaseModel


class AccessField(BaseModel):
    """
    field to generate encrypt_key
    """
    token_expire: int  #: user_token 过期时间, unix时间戳
    allow_method: List[str]  #: 能够进行请求的服务

    def gen_salt(self):
        """ 保证内容一致时生成一致的字符串用于加盐操作 """
        method = "".join(sorted(self.allow_method))
        return (str(self.token_expire) + method).lower()


class GrantToken(AccessField):
    """
    user_token 生成所用的字段
    """
    jwt_algorithm: str  #: 客户端jwt编码所用的算法
    verify_token: str  #: 用于验证, 用户将GrandToken中除 encrypy_key 之外内容发送给服务端,返回该key是否有效
    user_id: str  #: 用户id
    encrypt_key: str  #: 客户端jwt编码所用密钥


class Auth(BaseModel):
    """
    认证token生成所用基类
    """
    #: 用户名
    user_id: str
    #: 当前Unix时间戳,单位是秒,不是毫秒
    timestamp: int


class HashAuth(Auth):
    """
    :class:`fastapi_gen.oauth2.HashToken` 所用认证字段
    """
    code: str


class EncryptAuth(Auth, AccessField):
    # token: str  #: encrypt(jwt(GrantToken), GrantToken.encrypt_key, sha256(Auth.timestamp)[:12])
    """
    :class:`fastapi_gen.oauth2.EncryptToken` 所用认证字段
    """
    pass


class EncryptTokenConfig(BaseModel):
    secret_key: str
    algorithm_jwt: str
    salt_jwt: str
    salt_grand: str
    access_token_expire_second: int


class Config(BaseModel):
    token_config: EncryptTokenConfig
    allowed_acl: List[str]

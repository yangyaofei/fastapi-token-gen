import hashlib
import math
import time
import typing

import jwt
import pydantic
from fastapi.exceptions import HTTPException
from fastapi.requests import Request
from fastapi.security import OAuth2PasswordBearer
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from fastapi_token.encrypt import gen_key, gen_nonce_from_timestamp, encrypt
from fastapi_token.schemas import EncryptAuth, GrantToken, Auth, HashAuth, AccessField


class TimeExpireError(HTTPException):
    """ 当前的token过期"""

    def __init__(self, msg):
        super(TimeExpireError, self).__init__(
            status_code=HTTP_401_UNAUTHORIZED,
            detail=f"Not authenticated, auth fail timestamp not allowed"
                   f", Error msg : {msg}",
        )


class VerifyError(HTTPException):
    """ 验证不通过 """

    def __init__(self, msg):
        super(VerifyError, self).__init__(
            status_code=HTTP_401_UNAUTHORIZED,
            detail=f"Not authenticated, auth fail signature not correct"
                   f", Error msg : {msg}",
        )


class TokenExpireError(HTTPException):
    """ user_token过期 """

    def __init__(self, msg):
        super(TokenExpireError, self).__init__(
            status_code=HTTP_401_UNAUTHORIZED,
            detail=f"Not authenticated, auth fail token expire"
                   f", Error msg : {msg}",
        )


class TokenBase:
    """
    token 生成基类

    token生成中使用的变量:

    - user_id 用户id
    - user_token 用户获得的认证token, 用于生成最终的在请求中使用的token, 为字符串

    token生成和认证过程:

    1. 利用 user_id 以及其他信息生成 user_token 使用函数 :func:`gen_user_token`
    2. 客户端使用 :func:`gen_auth_token` 中的编码方式生成 :class:`fastapi_token_gen.schemas.Auth` 形式的数据
    3. 客户端使用 jwt以及约定的参数对上述生成的数据进行编码, 并组成 OAuth2 Bearer Token 形式发送给服务端
    4. 服务端获取 jwt编码的token后, 利用函数 :func:`auth` 对token进行认证

    """

    def gen_user_token(self, user_id: str, **config) -> str:
        """
        生成用户的token, 用于生成最终认证token

        :param user_id 用户ID用于生成认证token
        :param config
        :return:
        """
        raise NotImplementedError

    def gen_auth_token(self, user_id: str, user_token: str, **config) -> typing.Tuple[Auth, str]:
        """
        根据 user_token 生成最终的认证access_token
        :return:
        """
        raise NotImplementedError

    def auth(self, authorization: str) -> Auth:
        """
        认证, 利用access_token 进行认证
        :return:
        """
        raise NotImplementedError


class OAuth2(OAuth2PasswordBearer):
    def __init__(self, token_instance: TokenBase, **args):
        super().__init__(**args)
        self.token_instance = token_instance

    async def __call__(self, request: Request) -> Auth:
        authorization = await super().__call__(request)
        if not authorization:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
            )
        return self.token_instance.auth(authorization)


class HashToken(TokenBase):
    """
    利用Hash实现 ``user_token`` 分发 和最终 token 生成

    1. user_token 生成 利用 ``user_id`` 加盐md5生成
    2. access_token 生成 利用 ``user_token`` + 当前时间戳方式 hash生成

    """

    def __init__(self, secret_key: str, algorithm: str, auth_client: str, access_token_expire_second: int):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.auth_client = auth_client
        self.access_token_expire_second = access_token_expire_second

    def gen_user_token(self, user_id: str, **config) -> str:
        """
        生成用户的token, 用于生成最终认证token
        :return:
        """
        code = user_id + self.auth_client
        code = hashlib.md5(code.encode("utf-8")).hexdigest()
        return code

    def gen_auth_token(self, user_id: str, user_token: str, **config) -> typing.Tuple[HashAuth, str]:
        """
        根据 user_token 生成最终的认证access_token
        :return:
        """
        if "timestamp" not in config:
            timestamp = int(time.time())
        else:
            timestamp = config["timestamp"]
        code = user_token + str(timestamp)
        code = hashlib.md5(code.encode("utf-8")).hexdigest()
        hash_auth = HashAuth(user_id=user_id, timestamp=timestamp, code=code)
        return hash_auth, jwt.encode(hash_auth.dict(), self.secret_key, self.algorithm).decode("utf-8")

    def auth(self, authorization: str) -> HashAuth:
        """
        check the authorization

        认证使用的如下几个变量:

        1. auth_client: 服务内部key,用于生成user_token,不可公开
        2. user_token: 用户token,用于生成每次请求使用的token, 生成方法: ``hash(user_id + auth_clint)``
        3. user_id: 用户ID,用于辅助生产user_token
        4. timestamp: 时间戳,用于生成最终认证token
        5. code: 生成的用户认证信息, 生成方法: ``hash(user_token+timestamp)``
        6. secret_key: 服务每部key,用于进行JWT加密,公开给用户
        7. algorithm: JWT加密所用算法,公开给用户
        8. token: 最终生成的用于认证的token, 生成方法: ``jwt.encode(user_id, timestamp, code, secret_key, algorithm))``


        上述token由客户端生成后,在服务端被解码后,比较timestamp与当前时间的差值以及利用其中timestamp与user_id生成code后与token中
        的code进行比较,若相同则认证成功.

        :param authorization:
        :return: decode payload
        :exception HTTPException: Get 403 or 401
        """
        payload = HashAuth(**jwt.decode(authorization, self.secret_key, algorithms=[self.algorithm]))
        current_timestamp = time.time()

        if math.fabs(
                payload.timestamp - current_timestamp + self.access_token_expire_second / 2) > self.access_token_expire_second:
            raise TimeExpireError(
                f"current time is: {current_timestamp}, token time is : {payload.timestamp}, "
                f"access token expire second is : {self.access_token_expire_second}"
            )

        hash_auth, _ = self.gen_auth_token(
            timestamp=payload.timestamp,
            user_token=self.gen_user_token(user_id=payload.user_id),
            user_id=payload.user_id
        )
        if hash_auth.code != payload.code:
            raise VerifyError(f"This token is invalid, use a valid token")
        return payload


class EncryptToken(TokenBase):
    """
    在HTTP非加密环境下实现认证过程, 并使得认证token的生成不依赖服务端分配而是一次性分配一个密钥,在不暴露此密钥的情况下进行认证. 此过程中
    服务端也是无状态的,也就是不需要存储分配给客户的密钥.

    利用对称加密方式生成,利用JWS自带签名方式验证,支持增加 ``user_token`` 的过期时间和权限管理

    ``user_token`` 分发和认证过程:

    1. 利用 :class:`fastapi_token.schemas.AccessField` 中的信息生成 `key`, `nonce`,使用用chacha20ietf对内置文明进行加密
    获得密文作为客户端JWT加密密钥, 利用JWT生成包含上述生成信息和密文的token作为 ``user_token``

    2. 客户端解码后得到作为加密密钥的密文和生成信息, 使用加密密钥使用JWT编码 :class:`fastapi_token.schemas.EncryptAuth`,
    发送给服务端

    3. 服务端解码token后获得生成密钥的信息, 并重新生成密和初始向量并加密内置明文获取客户端JWT加密的密钥, 并利用此密钥验证客户端发送的token
    的签名, 从而验证客户端的 ``user_token``

    由于在上述过程中,客户端或者中间攻击者若修改发送的 :class:`fastapi_token.schemas.AccessField` 中的字段会导致最终服务端还原的密钥
    发生改变从而阻止对于 ``user_token`` 的修改, 重放攻击可以通过验证客户端发送的token中的时间戳部分防止.

    """

    def __init__(
            self,
            secret_key: str,
            algorithm_jwt: str,
            salt_jwt: str,
            salt_grand: str,
            access_token_expire_second: int,
    ):
        """

        :param secret_key: 总密钥,用于内部各种密钥的生成
        :param algorithm_jwt: jwt编码使用的算法
        :param salt_jwt: jwt编码使用的密钥的加盐内容
        :param salt_grand: user_token 生成的加盐内容
        :param access_token_expire_second: 客户端认证内容的过期时间
        """
        self.secret_key = secret_key
        self.secret_key_grand = hashlib.md5((self.secret_key + salt_grand).encode("utf-8")).hexdigest()
        self.secret_key_jwt = hashlib.md5((self.secret_key + salt_jwt).encode("utf-8")).hexdigest()
        self.algorithm_jwt = algorithm_jwt
        self.access_token_expire_second = access_token_expire_second
        self.secret_str = "衬衫的价格是九磅十五便士".encode("utf-8")

    def gen_key(self, salt: str = "", secret_key="") -> bytes:
        """
        生成用于对称加密的密钥,从 secret_key 生成

        :return:
        """
        return gen_key(
            (secret_key + salt if salt is not None else "").encode("utf-8")
        )

    def auth(self, authorization: str) -> EncryptAuth:
        try:
            payload = EncryptAuth(**jwt.decode(authorization, options={'verify_signature': False}))
        except pydantic.ValidationError as e:
            raise VerifyError(f"JWT token missing filed, mes: {e.errors()}")
        except jwt.DecodeError:
            raise VerifyError(f"This string is not a valid JWT token")
        access_field = AccessField(**payload.dict())
        key = self.gen_key(secret_key=self.secret_key_grand, salt=access_field.gen_salt())
        nonce = gen_nonce_from_timestamp(access_field.token_expire)
        encrypt_key = encrypt(self.secret_str, key=key, nonce=nonce).hex()
        try:
            payload = EncryptAuth(
                **jwt.decode(authorization, key=encrypt_key, algorithms=[self.algorithm_jwt]))
        except jwt.InvalidSignatureError:
            raise VerifyError(f"This token is invalid, use a valid token")
        current_timestamp = time.time()
        if math.fabs(
                payload.timestamp - current_timestamp + self.access_token_expire_second / 2) > self.access_token_expire_second:
            raise TimeExpireError(
                f"current time is: {current_timestamp}, token time is : {payload.timestamp}, "
                f"access token expire second is : {self.access_token_expire_second}")
        if payload.token_expire < current_timestamp:
            raise TokenExpireError(f"user token is expired. current time is : {current_timestamp}, "
                                   f"user token expired time is : {payload.token_expire}")
        return payload

    def check_user_token(self, user_token: str):
        try:
            grant_token = GrantToken(
                **jwt.decode(user_token, key=self.secret_key_jwt, algorithms=[self.algorithm_jwt])
            )
            return grant_token
        except jwt.InvalidSignatureError:
            raise VerifyError(f"User token verify fail, this token may not the key in this system,"
                              f"Info in this token is : {jwt.decode(user_token, options={'verify_signature': False})}")
        except jwt.DecodeError:
            raise VerifyError(f"This string is not a valid JWT token")

    def gen_user_token(self, user_id: str, access_field: typing.Optional[AccessField] = None, **config) -> str:
        """
        生成用户的token, 用于生成最终认证token

        :param user_id :用户ID
        :param access_field : 生成的token的权限,不指定则生成最大权限的token
        :return: jwt 格式的 user_token
        """
        if not access_field:
            access_field = AccessField(
                token_expire=config.get(
                    "expire_timestamp",
                    (int(time.time()) + self.access_token_expire_second)
                ),
                allow_method=["*"]
            )
        key = self.gen_key(secret_key=self.secret_key_grand, salt=access_field.gen_salt())
        nonce = gen_nonce_from_timestamp(access_field.token_expire)

        grand_token = GrantToken(
            jwt_algorithm=self.algorithm_jwt,
            user_id=user_id,
            verify_token=self.gen_key(secret_key=self.secret_key_grand, salt=key.hex()).hex(),
            encrypt_key=encrypt(self.secret_str, key=key, nonce=nonce).hex(),
            **access_field.dict(),
        )
        return jwt.encode(grand_token.dict(), self.secret_key_jwt, self.algorithm_jwt)

    @staticmethod
    def gen_auth_token(user_id: str, user_token: str, **config) -> typing.Tuple[EncryptAuth, str]:
        """
        这里 user_token 为生成认证的jwt代码
        根据 user_token 生成最终的认证access_token

        :param user_id
        :param user_token
        :param config
        :return: 认证内容以及jwt加密后内容
        """
        grand_token = GrantToken(**jwt.decode(user_token, options={"verify_signature": False}))
        access_field = AccessField(**grand_token.dict())
        timestamp = config.get("timestamp", int(time.time()))
        encrypt_auth = EncryptAuth(user_id=user_id, timestamp=timestamp, **access_field.dict())
        return encrypt_auth, jwt.encode(
            encrypt_auth.dict(),
            key=grand_token.encrypt_key,
            algorithm=grand_token.jwt_algorithm,
        )

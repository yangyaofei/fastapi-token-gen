from fastapi.requests import Request
from fastapi.exceptions import HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
from fastapi.security import OAuth2PasswordBearer
import jwt
import base64
import hashlib
from fastapi_token.schemas import EncryptAuth, GrandToken, Auth, HashAuth, AccessField
from fastapi_token.encrypt import gen_key, gen_none_from_timestamp, encrypt, decrypt
import time
import typing
import math
import json


class TimeExpireError(Exception):
    """ 当前的token 过期"""
    pass


class VerifyError(Exception):
    pass


class TokenExpireError(Exception):
    """ user_token 过期"""
    pass


class TokenBase:
    def gen_user_token(self, user_id: str, **config) -> str:
        """
        生成用户的token, 用于生成最终认证token
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
        try:
            return self.token_instance.auth(authorization)
        except TimeExpireError:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated, auth fail timestamp not allowed",
            )
        except VerifyError:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated, auth fail signature not correct",
            )
        except TokenExpireError:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated, auth fail token exprie",
            )


class HashToken(TokenBase):
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
        return hash_auth, jwt.encode(hash_auth.dict(), self.secret_key, self.algorithm)

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
        :exception HTTPException : Get 403 or 401
        """
        payload = HashAuth(**jwt.decode(authorization, self.secret_key, algorithms=[self.algorithm]))

        if math.fabs(
                payload.timestamp - time.time() + self.access_token_expire_second / 2) > self.access_token_expire_second:
            raise TimeExpireError()
        hash_auth, _ = self.gen_auth_token(
            timestamp=payload.timestamp,
            user_token=self.gen_user_token(user_id=payload.user_id),
            user_id=payload.user_id
        )
        if hash_auth.code != payload.code:
            raise VerifyError()
        return payload


class EncryptToken(TokenBase):
    """
    user_token -> encrypt(privilege + time_expire)
    token -> RAS(pub_key, user_id, timestamp, user_token)

    auth:
    user_id, timestamp, user_token -> RSA(pri_key, token)


    分发token : GrandToken -> jwt(GrandToken)
               encrypt_key -> base64_encode((secret_key + json(AccessField)).encode("utf-8")))

    请求: jwt(EncryptAuth) token -> encrypt(
                                        method: chacha20,
                                        payload: jwt(GrandToken)
                                        key: encrypt_key-> base64_decode
                                        none: timestamp(utf-8).SHA256()[:12]
                                    )
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

        :param secret_key: 总密钥
        :param algorithm:
        :param auth_client:
        :param access_token_expire_second:
        :param args:
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
        payload = EncryptAuth(**jwt.decode(authorization, verify=False))
        access_field = AccessField(**payload.dict())
        key = self.gen_key(secret_key=self.secret_key_grand, salt=access_field.gen_salt())
        none = gen_none_from_timestamp(access_field.token_expire)
        encrypt_key = encrypt(self.secret_str, key=key, none=none).hex()
        try:
            payload = EncryptAuth(
                **jwt.decode(authorization, verify=True, key=encrypt_key, algorithms=[self.algorithm_jwt]))
        except jwt.exceptions.InvalidSignatureError:
            raise VerifyError()
        if math.fabs(
                payload.timestamp - time.time() + self.access_token_expire_second / 2) > self.access_token_expire_second:
            raise TimeExpireError()
        if payload.token_expire < time.time():
            raise TokenExpireError()
        return payload

    def gen_user_token(self, user_id: str, access_field: typing.Optional[AccessField] = None, **config) -> str:
        """
        生成用户的token, 用于生成最终认证token
        :return:
        """
        if not access_field:
            access_field = AccessField(
                token_expire=int(time.time()) + self.access_token_expire_second,
                allow_method=["*"]
            )
        key = self.gen_key(secret_key=self.secret_key_grand, salt=access_field.gen_salt())
        none = gen_none_from_timestamp(access_field.token_expire)

        grand_token = GrandToken(
            jwt_algorithm=self.algorithm_jwt,
            user_id=user_id,
            varify_token=self.gen_key(secret_key=self.secret_key_grand, salt=key.hex()).hex(),
            encrypt_key=encrypt(self.secret_str, key=key, none=none).hex(),
            **access_field.dict(),
        )
        return jwt.encode(grand_token.dict(), self.secret_key_jwt, self.algorithm_jwt)

    @staticmethod
    def gen_auth_token(user_id: str, user_token: str, **config) -> typing.Tuple[EncryptAuth, str]:
        """
        这里 user_token 为生成认证的jwt代码
        根据 user_token 生成最终的认证access_token
        :return:
        """
        grand_token = GrandToken(**jwt.decode(user_token, verify=False))
        access_field = AccessField(**grand_token.dict())
        timestamp = config.get("timestamp", int(time.time()))
        encrypt_auth = EncryptAuth(user_id=user_id, timestamp=timestamp, **access_field.dict())
        return encrypt_auth, jwt.encode(
            encrypt_auth.dict(),
            key=grand_token.encrypt_key,
            algorithm=grand_token.jwt_algorithm,

        )

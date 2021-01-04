from fastapi.requests import Request
from fastapi.exceptions import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN
from fastapi.security import OAuth2PasswordBearer
import jwt
import base64
import hashlib
from fastapi_token.schemas import EncryptAuth, GrandToken, Auth, HashAuth, GenToken
from fastapi_token.encrypt import gen_key, gen_none_from_timestamp, encrypt, decrypt
import time
import math
import json


class OAuth2TokenBase(OAuth2PasswordBearer):
    """
    user_id: 用户ID, 任何最终token都可以使用 user_id 与当前时间戳组合生成
    """

    async def __call__(self, request: Request) -> Auth:
        authorization = await super().__call__(request)
        return self.auth(authorization)

    def auth(self, authorization: str) -> Auth:
        """进行认证"""
        raise NotImplementedError

    def gen_user_token(self, user_id, timestamp=-1, payload=None):
        """
        根据时间限制和用户id生成用户token

        :param payload: 想一起放入token中的信息
        :param timestamp:
        :param user_id
        """
        raise NotImplementedError

    def gen_auth_token(self, user_id, user_token, timestamp):
        """生成最终的token"""
        raise NotImplementedError


class OAuth2TokenBasic(OAuth2TokenBase):
    """
    make a OAuth2 authorization

    :param secret_key:
    :param algorithm:
    :param auth_client:
    :param access_token_expire_second:
    :param args:

    """

    def __init__(self, secret_key: str, algorithm: str, auth_client: str, access_token_expire_second: int, **args):
        super().__init__(**args)
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.auth_client = auth_client
        self.access_token_expire_second = access_token_expire_second

    def auth(self, authorization: str) -> Auth:
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
        if not authorization:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
            )
        payload = HashAuth(**jwt.decode(authorization, self.secret_key, algorithms=[self.algorithm]))

        if math.fabs(
                payload.timestamp - time.time() + self.access_token_expire_second / 2) > self.access_token_expire_second:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated, auth fail timestamp not allowed",
            )
        md5 = self.gen_auth_token(self.gen_user_token(str(payload.user_id)), payload.timestamp)
        if md5 != payload.code:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated, auth fail code not correct",
            )
        return payload

    def gen_auth_token(self, user_id, user_token, timestamp=-1):

        timestamp = int(time.time())
        code = self.gen_auth_code(user_token, timestamp)
        return HashAuth(user_id=user_id, timestamp=timestamp, code=code)

    def gen_user_token(self, username, timestamp=-1, payload=None):
        """
        :param payload:
        :param username:
        :param timestamp:
        :return:
        """
        md5 = username + self.auth_client
        md5 = hashlib.md5(md5.encode("utf-8")).hexdigest()
        return md5

    @staticmethod
    def gen_auth_code(user_token, timestamp):
        """
        Generate a token using user_token and timestamp

        :param user_token:
        :param timestamp:
        :return:
        """
        md5 = user_token + str(timestamp)
        md5 = hashlib.md5(md5.encode("utf-8")).hexdigest()
        return md5

    def encode_auth(self, auth_data: dict) -> bytes:
        """
        Encode authorization dict with jwt

        :param auth_data: The authorization dict wish to encode
        :return: An encoded token ues with jwt and oauth2
        """
        return jwt.encode(auth_data, self.secret_key, self.algorithm)


class OAuth2TokenEncrypt(OAuth2TokenBase):
    """
    user_token -> encrypt(privilege + time_expire)
    token -> RAS(pub_key, user_id, timestamp, user_token)

    auth:
    user_id, timestamp, user_token -> RSA(pri_key, token)


    分发token : GrandToken -> jwt(GrandToken)
               encrypt_key -> base64_encode((secret_key + json(GenToken)).encode("utf-8")))

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
            **args
    ):
        """

        :param secret_key: 总密钥
        :param algorithm:
        :param auth_client:
        :param access_token_expire_second:
        :param args:
        """
        super().__init__(**args)
        self.secret_key = secret_key
        self.secret_key_grand = hashlib.md5((self.secret_key + salt_grand).encode("utf-8")).hexdigest()
        self.secret_key_jwt = hashlib.md5((self.secret_key + salt_jwt).encode("utf-8")).hexdigest()
        self.algorithm_jwt = algorithm_jwt
        self.access_token_expire_second = access_token_expire_second

    def gen_key(self, salt=None):
        """
        生成用于对称加密的密钥,从 secret_key 生成
        :return:
        """
        return base64.b64encode(
            gen_key(
                (self.secret_key + salt if salt is not None else "").encode("utf-8")
            )
        ).decode("ascii")

    @staticmethod
    def encrypt(payload: str, timestamp: int, key: str):
        """
        加密方式: payload -> encode("utf-8") -> encrypt -> base64

        :param key:
        :param timestamp:
        :param payload:
        :return:
        """
        key = base64.b64decode(key)
        none = gen_none_from_timestamp(timestamp)
        data = encrypt(payload.encode("utf-8"), key=key, none=none)
        return base64.b64encode(data)

    @staticmethod
    def decrypt(payload: str, timestamp: int, key: str):
        """
        解密方式: payload -> decode-base64 -> decrypt -> decode("utf-8")
        :param timestamp:
        :param key:
        :param payload:
        :return:
        """

        key = base64.b64decode(key)
        none = gen_none_from_timestamp(timestamp)
        data = base64.b64decode(payload)
        data = decrypt(data, key, none)
        return data.decode("utf-8")

    def auth(self, authorization: str) -> Auth:
        if not authorization:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
            )
        payload = EncryptAuth(**jwt.decode(authorization, self.secret_key_jwt, algorithms=[self.algorithm_jwt]))
        if math.fabs(
                payload.timestamp - time.time() + self.access_token_expire_second / 2) > self.access_token_expire_second:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="Not authenticated, auth fail timestamp not allowed",
            )
        encrypt_key = self.gen_key(GenToken(**payload.dict()).json())
        grand_token = self.decrypt(payload=payload.token, key=encrypt_key, timestamp=payload.timestamp)
        grand_token = GrandToken(**jwt.decode(grand_token, algorithms=[self.algorithm_jwt], key=self.secret_key_jwt))
        assert grand_token
        return payload

    def gen_user_token(self, user_id: str, timestamp: int = -1, payload=None):
        """

        :param user_id:
        :param timestamp:
        :param payload:
        :return:
        """
        return gen_key((user_id + str(timestamp) + payload if payload is not None else "").encode("utf-8"))


    def gen_auth_token(self, user_id, user_token, timestamp):
        """

        :param user_id:
        :param user_token:
        :param timestamp:
        :return:
        """
        pass

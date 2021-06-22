import time
import typing

from fastapi import APIRouter, Body, Depends
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from fastapi_token.acl import ACL
from fastapi_token.oauth2 import EncryptToken, GrantToken, EncryptAuth, AccessField
from fastapi_token.schemas import Config


class TokenRouter:
    responses = {
        HTTP_401_UNAUTHORIZED: {"description": "Unauthorized"},
        HTTP_403_FORBIDDEN: {"description": "No Authorization"}
    }

    def __init__(self, config: Config):
        self.router = APIRouter(responses=self.responses)
        self.config: Config = config

        @self.router.get(
            "/token/user_token/show",
            response_model=GrantToken,
            dependencies=[Depends(ACL(self.config.allowed_acl))]
        )
        def show_user_token(user_token: str) -> GrantToken:
            return EncryptToken(**self.config.token_config.dict()).check_user_token(user_token)

        @self.router.get(
            "/token/auth_token/show",
            response_model=EncryptAuth,
            dependencies=[Depends(ACL(self.config.allowed_acl))]
        )
        def show_auth_token(auth_token: str) -> EncryptAuth:
            return EncryptToken(**self.config.token_config.dict()).auth(auth_token)

        @self.router.post(
            "/token/user_token/generate",
            response_model=dict,
            dependencies=[Depends(ACL(self.config.allowed_acl))]
        )
        def generate_user_token(
                user_id: str = Body(...),
                expire_time: int = Body(default=3600),
                allow_method: typing.Optional[typing.List[str]] = Body(default=None)
        ):
            access_field = AccessField(
                token_expire=expire_time + int(time.time()),
                allow_method=allow_method if allow_method is not None else ["*"]
            )
            return {
                "user_token": EncryptToken(**self.config.token_config.dict()).gen_user_token(
                    user_id=user_id,
                    access_field=access_field,
                )
            }

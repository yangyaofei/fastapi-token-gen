from typing import List

from cidrize import cidrize, IPNetwork
from fastapi import Request
from fastapi.exceptions import HTTPException
from fastapi.logger import logger
from starlette.status import HTTP_405_METHOD_NOT_ALLOWED


class ACLException(HTTPException):
    def __init__(self):
        super(ACLException, self).__init__(
            status_code=HTTP_405_METHOD_NOT_ALLOWED,
            detail=f"No authentication to do this",
        )


class ACL:
    def __init__(self, acl: List[str]):
        self.acl: List[IPNetwork] = list()
        for acl_item in acl:
            self.acl += cidrize(acl_item)

    async def __call__(self, request: Request) -> Request:
        logger.info(f"Check {request.client.host} in ACL list")
        for acl_item in self.acl:
            if request.client.host in acl_item:
                return request
        raise ACLException()

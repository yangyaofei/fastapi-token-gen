# Fastapi-Token-Gen

`fastapi-token-gen` is a module for `fastapi` to generate token using `JWT`

`fastapi-token-gen` 是一个用于`fastapi`的认证库, 使用 `JWT` 传递 Token.

[![Documentation Status](https://readthedocs.org/projects/fastapi-token-gen/badge/?version=latest)](https://fastapi-token-gen.readthedocs.io/en/latest/?badge=latest)
[![PyPI version](https://badge.fury.io/py/fastapi-token-gen.svg)](https://badge.fury.io/py/fastapi-token-gen)

- Documentation: https://fastapi-token-gen.rtfd.io
- Free software: [MIT license](http://opensource.org/licenses/MIT)


在HTTP下, 简单的 `jwt` 的认证方式是不安全的, 会被进行重放攻击. 本module使用哈希
和加密算法, 分发给客户端一个key, 客户端使用该key根据约定方式进行编码获得用于请求的 `token`,
利用时间戳防止重放攻击.

现有库中的 `EncryptToken` 类对应的方法在客户端只需按照约定密钥进行 `jwt` 编码即可,利用该签名
进行认证,较为便捷

使用方式是在 `fastapi` 中使用继承自 `fastapi` 的 `OAuth2PasswordBearer` 
的 `fastapi_token.oauth2.OAuth2`, 并将上述的类的实例传递给 `fastapi_token.oauth2.OAuth2`
即可
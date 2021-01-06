# Fastapi-Token-Gen

`fastapi-token-gen` is a module for `fastapi` to generate token follow `oauth2`

`fastapi-token-gen` 是一个用于`fastapi`的认证库,符合`oauth2`认证.

在HTTP下, 简单的`jwt` + `oauth2`的认证方式是不安全的, 会被进行重放攻击. 本module使用哈希
和加密算法, 分发给客户端一个key, 客户端使用该key根据约定方式进行编码获得用于请求的 `token`,
防止重放攻击的方式利用的是时间戳,并对时间戳进行哈希或者加签名的方式.

现有库中的 `EncryptToken` 类对应的方法在客户端只需按照约定密钥进行 `jwt` 编码即可,利用该签名
进行认证,较为便捷

使用方式是在 `fastapi` 中使用 继承自 `fastapi` 的 `OAuth2PasswordBearer` 
的 `fastapi_token.oauth2.OAuth2`, 并将上述的类的实例传递给 `fastapi_token.oauth2.OAuth2`
即可
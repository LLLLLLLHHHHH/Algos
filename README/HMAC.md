
# HMAC 实现分析

## 1. 总结
HMAC (Hash-based Message Authentication Code) 是基于哈希的带密钥消息认证码，遵循 RFC 2104。
- **核心功能**: 使用密钥与消息计算固定长度 MAC；支持底层哈希为 SHA-256、SHA-384、SHA-512、MD5、SHA-1、SHA3-256、SHA3-512 等；C 当前实现 HMAC-SHA256（ipad 0x36、opad 0x5c）；JS 支持上述多种哈希，Node 下同步/异步、浏览器下异步。
- **标准兼容**: 符合 RFC 2104。
- **实现方式**: C 在 `c/HMAC` 中基于 `c/SHA256` 实现 `hmac_sha256`；JS 在 `js/HMAC` 中封装 Node `crypto.createHmac` 或 Web Crypto `crypto.subtle.sign('HMAC', key, data)`。

## 2. 特点与特征

### 双哈希结构
- **密钥块**: 密钥补齐/截断为块长（SHA-256 为 64 字节），与 ipad (0x36) 异或得 `K_ipad`，与 opad (0x5c) 异或得 `K_opad`。
- **计算**: `H(K_opad || H(K_ipad || message))`，输出长度与底层哈希一致（如 SHA-256 为 32 字节）。
- **指纹特征**: 字符串常含 HMAC、hmac、HMAC-SHA256/SHA384/SHA512、ipad、opad；u32 常含 0x36、0x5c（标为 supportive）。

### 接口
- C: `hmac_sha256(key, key_len, msg, msg_len, out)`，输出 32 字节。
- JS: `hmacSync(key, message, hashAlg)`、`hmacAsync(key, message, hashAlg)`，`hashAlg` 如 `'sha256'`、`'sha384'`、`'sha512'` 等。

## 3. 魔改建议

- **多哈希扩展**: 在 C 端增加 `hmac_sha384`、`hmac_sha512`，复用现有 SHA512 与 HMAC 双哈希框架。
- **常量时间**: 比较 MAC 时使用常量时间比较，避免时序侧信道。
- **与 TLS/JWT 等结合**: 文档中可补充 HMAC-SHA256 在 TLS 1.2、JWT 等中的典型用法。

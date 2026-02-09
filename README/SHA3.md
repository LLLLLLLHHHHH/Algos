
# SHA3 (SHA3-256 / SHA3-512) 实现分析

## 1. 总结
SHA3 基于 Keccak 海绵结构 (FIPS 202)，提供 SHA3-256 (32 字节) 与 SHA3-512 (64 字节) 等变体。
- **核心功能**: 任意长度输入经海绵吸收/挤压得到固定长度哈希；C 为**手写算法源码**（Keccak-f[1600] 24 轮 θ/ρ/π/χ/ι + SHA3 填充与海绵），无外部库；JS 使用 Node 19+ `sha3-256`/`sha3-512` 或 Web Crypto。
- **标准兼容**: 符合 FIPS 202 (SHA-3)。
- **实现方式**: C 在 `c/SHA3` 中完整实现 Keccak-f[1600] 与 SHA3-256/512；JS 在 `js/SHA3` 中封装 Node/Web Crypto。

## 2. 特点与特征

### Keccak 与海绵
- **结构**: 海绵函数包含吸收与挤压阶段，内部为 Keccak-f[1600] 置换（1600 位状态）。
- **指纹特征**: 字符串常含 Keccak、sha3_init/update/final、KeccakF1600、keccakf；u32 常含 0x00000001、0x00008082、0x80000000 等 Keccak 相关常数。

### 接口
- C: `sha3_256(data, len, hash)`、`sha3_512(data, len, hash)`，无外部依赖。
- JS: `sha3_256Sync`/`sha3_256Async`、`sha3_512Sync`/`sha3_512Async`，环境支持时同步可用。

## 3. 魔改建议

- **性能**: Keccak-f 24 轮可做循环展开或配合 SIMD；亦可按需 `#ifdef` 链接 OpenSSL 以使用硬件加速。
- **HMAC-SHA3**: 在 HMAC 模块中支持 SHA3-256/SHA3-512 作为底层哈希（部分环境已支持）。

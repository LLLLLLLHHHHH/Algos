
# RSA C语言实现分析

## 1. 总结
这是一个完整的 RSA (Rivest-Shamir-Adleman) 公钥加密算法的 C 语言实现，支持最高 2048 位密钥（默认）。
- **核心功能**: 提供了 RSA 公钥加密、私钥解密、私钥加密（签名）、公钥解密（验签）的完整功能。
- **模块化**: 实现了独立的大数运算库 (`bigNum.c/h`)，负责处理 RSA 所需的大整数运算。
- **标准兼容**: 实现了 PKCS#1 v1.5 填充方案（Padding），符合标准的 RSA 加密流程。

## 2. 特点与特征

### 大数运算库 (BigNum)
- **自定义实现**: 不依赖 OpenSSL 或 GMP 等外部库，完全从零实现了 `bn_add`, `bn_sub`, `bn_mul`, `bn_div`, `bn_mod`, `bn_mod_exp` 等核心函数。
- **基于 32 位字**: 使用 `uint32_t` 作为大数的基本单元 (`bn_t`)，`uint64_t` 用于处理乘法进位 (`dbn_t`)，适合 32 位及以上系统。
- **定长数组**: 使用静态数组 `bn_t[BN_MAX_DIGITS]` 存储大数，避免了动态内存分配 (`malloc`)，适合嵌入式环境，但限制了支持的最大位数（目前配置为支持 2048 位）。

### RSA 核心逻辑
- **密钥结构**: 定义了 `rsa_pk_t` (公钥) 和 `rsa_sk_t` (私钥) 结构体，私钥结构体中包含了 CRT (中国剩余定理) 所需的参数 (`prime1`, `prime2`, `exponent1`, `exponent2`, `coefficient`)。
- **中国剩余定理 (CRT) 加速**: `rsa_private_encrypt/decrypt` 函数利用 CRT (`private_block_operation`) 进行私钥运算，相比直接模幂运算，速度提升约 3-4 倍。
- **蒙哥马利模乘 (未显式实现)**: 当前的 `bn_mod_exp` 使用了二进制从右向左的模幂算法，但底层的模乘 `bn_mod_mul` 是基于除法的 (`bn_div`)，效率较低。

### 填充方案 (Padding)
- **PKCS#1 v1.5**: 实现了标准的块填充。
    - **加密**: 块类型 02 (`00 02 <随机非零字节> 00 <数据>`)。代码中包含了一个简单的随机数填充逻辑。
    - **签名**: 块类型 01 (`00 01 <FF...> 00 <数据>`)。

## 3. 魔改建议

### 性能飞跃：蒙哥马利约减 (Montgomery Reduction)
当前实现的瓶颈在于模乘运算使用了除法。
- **魔改点**: 实现蒙哥马利乘法 (`MonPro`) 替代 `bn_mod_mul`。
- **效果**: 将模乘中的除法运算转化为移位和加法，在 RSA 这种需要大量模乘的场景下，性能可提升数倍。

### 安全增强：OAEP 填充
PKCS#1 v1.5 填充已知存在 Bleichenbacher 攻击风险。
- **魔改点**: 实现 **OAEP (Optimal Asymmetric Encryption Padding)**。需要引入哈希函数（如 SHA-1 或 SHA-256）和 MGF1 (Mask Generation Function)。
- **效果**: 提供语义安全性 (Semantic Security)，符合现代加密标准。

### 侧信道防御
当前的大数运算（特别是除法和模幂）存在数据依赖的分支，容易受到计时攻击。
- **魔改点**: 实现恒定时间 (Constant-Time) 的大数乘法和模幂算法。
- **魔改点**: 在 CRT 计算中引入随机盲化 (Blinding)，防止故障注入攻击。

### 密钥生成 (Key Generation)
当前代码只包含加密/解密，没有密钥生成功能。
- **魔改点**: 实现素数生成算法（如 Miller-Rabin 素性测试），允许在设备上动态生成 RSA 密钥对。

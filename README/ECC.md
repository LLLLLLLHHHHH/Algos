
# ECC (Elliptic Curve Cryptography) C语言实现分析

## 1. 总结
这是一个轻量级且功能完整的椭圆曲线密码学 (ECC) C 语言实现，源自 `micro-ecc` 或类似库。
- **支持曲线**: 实现了 NIST 标准曲线 secp128r1, secp192r1, secp256r1, 和 secp384r1（通过 `ECC_CURVE` 宏配置）。默认使用 secp256r1。
- **核心功能**:
    - **ECDH (Elliptic Curve Diffie-Hellman)**: 密钥交换协议，用于生成共享密钥。
    - **ECDSA (Elliptic Curve Digital Signature Algorithm)**: 数字签名算法，用于生成和验证签名。
- **依赖**: 代码高度独立，仅依赖标准 C 库和系统级随机数生成器（Windows 下用 `CryptGenRandom`，Unix 下用 `/dev/urandom`）。

## 2. 特点与特征

### 优化的数学运算
- **大数运算 (VLI)**: 实现了一套大数（Very Large Integer）运算库，包括加减乘除、移位、模运算等。
    - 特别优化了针对特定曲线素数 `curve_p` 的快速模运算 (`vli_mmod_fast`)，利用了 NIST 曲线素数的特殊结构（伪梅森素数）来加速取模。
    - 提供了 `uint128_t` 支持（如果编译器支持）来加速 64 位乘法。
- **蒙哥马利阶梯算法 (Montgomery Ladder)**: 在点乘 (`EccPoint_mult`) 中使用了 Montgomery Ladder 算法。
    - **抗侧信道攻击**: 无论标量位是 0 还是 1，都执行相同数量的点加和点倍运算，从而抵抗简单功耗分析 (SPA) 和计时攻击。
    - **共Z坐标 (Co-Z Arithmetic)**: 使用 Jacobian 坐标系的变体（XYcZ），避免了昂贵的模逆运算，直到最后一步才将其转换回仿射坐标。

### 紧凑的公钥格式
- **压缩公钥**: 代码默认支持并使用压缩公钥格式（`ECC_BYTES + 1` 字节）。
    - 第一个字节 (`0x02` 或 `0x03`) 指示 Y 坐标的奇偶性。
    - 剩余字节存储 X 坐标。
    - `ecc_point_decompress` 函数负责在验证签名或计算共享密钥时恢复 Y 坐标（涉及模平方根计算 `mod_sqrt`）。

### 安全性设计
- **随机数生成**: 封装了 `getRandomNumber` 函数，根据不同操作系统调用强随机数源，这对私钥生成 (`ecc_make_key`) 和 ECDSA 签名 (`ecdsa_sign`) 至关重要。
- **参数验证**: 在关键操作（如公钥解压、签名验证）中包含基本的范围检查 (`vli_cmp(curve_n, ...)`), 防止无效点攻击。

## 3. 魔改建议

### 更换曲线 (SM2 / Curve25519)
当前代码针对 NIST 曲线进行了硬编码优化。
- **魔改点**:
    - 修改 `ECC_CURVE` 相关的宏定义（`Curve_P`, `Curve_B`, `Curve_G`, `Curve_N`）为 **SM2** 或 **Curve25519** 的参数。
    - **关键难点**: `vli_mmod_fast` 是针对特定 NIST 素数形式优化的。如果换成 SM2 素数，需要重写该函数以利用 SM2 素数的快速归约公式。对于 Curve25519，则需要完全不同的 Montgomery 曲线算术逻辑。

### 确定性 ECDSA (RFC 6979)
当前的 `ecdsa_sign` 每次签名都依赖随机数 `k`。如果随机数生成器故障，私钥可能泄露。
- **魔改点**: 实现 RFC 6979，不再随机生成 `k`，而是通过 `HMAC-SHA256(private_key || hash)` 确定性地推导 `k`。
- **效果**: 签名过程不再依赖 RNG，生成的签名是确定的，且安全性不降低。

### 侧信道防御增强
虽然使用了 Montgomery Ladder，但在模逆 (`vli_modInv`) 和模平方根 (`mod_sqrt`) 等函数中可能仍存在数据依赖的分支。
- **魔改点**: 审查并重写这些辅助函数，确保所有操作都是恒定时间的 (Constant-Time)，避免使用基于数据的 `if` 分支或 `while` 循环。

### 汇编优化
对于嵌入式平台（如 ARM Cortex-M），C 语言实现的大数乘法可能不够快。
- **魔改点**: 使用内联汇编重写 `vli_mult`, `vli_add`, `vli_sub` 等核心函数，利用目标平台的特定指令（如 `UMLAL`）加速大数运算。

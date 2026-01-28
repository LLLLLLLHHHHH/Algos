# Algos - 密码学算法库

本项目汇集了多种常用密码学算法的 C 语言和 JavaScript 实现，并附带了详细的算法分析文档。旨在为开发者提供清晰、独立且易于移植的参考实现。

## 📂 目录结构

- `c/`: 算法的 C 语言源代码及测试程序。
- `js/`: 算法的 JavaScript 移植版本。
- `README/`: 各个算法的详细分析文档（包含总结、特点及魔改建议）。

## 🛠️ 算法列表

### 🔐 对称加密 (Symmetric Encryption)

| 算法 | C 实现 | JS 实现 | 详细分析 | 说明 |
| :--- | :---: | :---: | :---: | :--- |
| **AES** | [C](c/AES) | - | [Analysis](README/AES.md) | 高级加密标准，支持 ECB/CBC/CTR 模式 |
| **SM4** | [C](c/SM4) | [JS](js/SM4) | [Analysis](README/SM4.md) | 国密分组密码算法 |
| **ChaCha20** | [C](c/ChaCha20) | [JS](js/ChaCha20) | [Analysis](README/ChaCha20.md) | 高效流密码，RFC 7539 标准 |
| **Salsa20** | [C](c/Salsa20) | [JS](js/Salsa20) | [Analysis](README/Salsa20.md) | ChaCha20 的前身，高性能流密码 |
| **RC4** | [C](c/RC4) | - | [Analysis](README/RC4.md) | 经典流密码（注：已不再推荐用于安全场景） |
| **TEA** | [C](c/TEA) | [JS](js/TEA) | [Analysis](README/TEA.md) | 微型加密算法，极简设计 |
| **XTEA** | [C](c/XTEA) | [JS](js/XTEA) | [Analysis](README/XTEA.md) | TEA 的扩展版，修复密钥弱点 |
| **XXTEA** | [C](c/XXTEA) | [JS](js/XXTEA) | [Analysis](README/XXTEA.md) | TEA 的修正版，支持变长块 |

### 🔑 非对称加密 (Asymmetric Encryption)

| 算法 | C 实现 | JS 实现 | 详细分析 | 说明 |
| :--- | :---: | :---: | :---: | :--- |
| **RSA** | [C](c/RSA) | - | [Analysis](README/RSA.md) | 经典的公钥加密与签名算法，包含 BigNum 库 |
| **ECC** | [C](c/ECC) | - | [Analysis](README/ECC.md) | 椭圆曲线密码学 (NIST 曲线) |
| **SM2** | [C](c/SM2) | - | [Analysis](README/SM2.md) | 国密椭圆曲线公钥密码算法 |

### #️⃣ 哈希算法 (Hashing)

| 算法 | C 实现 | JS 实现 | 详细分析 | 说明 |
| :--- | :---: | :---: | :---: | :--- |
| **MD5** | [C](c/MD5) | - | [Analysis](README/MD5.md) | 广泛使用的消息摘要算法 |
| **SHA-1** | [C](c/SHA1) | [JS](js/SHA1) | [Analysis](README/SHA1.md) | 安全哈希算法 1 |
| **SHA-256** | [C](c/SHA256) | - | [Analysis](README/SHA256.md) | SHA-2 系列中最常用的变体 |
| **SM3** | [C](c/SM3) | [JS](js/SM3) | [Analysis](README/SM3.md) | 国密密码杂凑算法 |
| **MurmurHash** | [C](c/murmurhash) | - | [Analysis](README/MurmurHash.md) | 高性能非加密哈希算法 |

### 🔡 编码 (Encoding)

| 算法 | C 实现 | JS 实现 | 详细分析 | 说明 |
| :--- | :---: | :---: | :---: | :--- |
| **Base64** | [C](c/base64) | - | [Analysis](README/base64.md) | 二进制到文本的编码方案 |

## 🚀 使用说明

### C 语言版本
每个算法目录下通常包含：
- `.c / .h` 文件：核心算法实现。
- `main.c`：测试用例或示例代码。
- `build.bat` 或 `build.sh`：编译脚本。

您可以直接进入相应目录进行编译，例如：
```bash
cd c/SM4
gcc main.c SM4.c -o sm4_test
./sm4_test
```

### JavaScript 版本
JS 版本位于 `js/` 目录下，通常为纯 ES 实现，可直接在 Node.js 环境或浏览器中使用。

## ⚠️ 免责声明

本仓库代码主要用于**学习、研究和参考**。虽然我们尽力确保实现的正确性，但在用于生产环境（特别是涉及高价值数据的安全系统）之前，请务必进行严格的安全审计和测试。

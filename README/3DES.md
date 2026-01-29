# 3DES (Triple DES) Algorithm Implementation Analysis

## 1. 总结 (Summary)
**3DES (Triple Data Encryption Algorithm, TDEA)** 是 DES 算法的一种增强形式，旨在解决 DES 密钥长度过短（56位）导致的安全问题。
它通过对每个数据块执行三次 DES 操作（加密-解密-加密，即 EDE 模式）来增加密钥空间，从而显著提高了抵御暴力破解攻击的能力。

## 2. 特点与特征 (Features & Characteristics)

### 2.1 核心机制 (EDE Mode)
3DES 的标准实现通常采用 **EDE (Encrypt-Decrypt-Encrypt)** 模式：
*   **加密过程**：$C = E_{K3}(D_{K2}(E_{K1}(P)))$
*   **解密过程**：$P = D_{K1}(E_{K2}(D_{K3}(C)))$

这种设计的一个主要优点是兼容性：当 $K1 = K2 = K3$ 时，3DES 的结果与标准 DES 完全一致。

### 2.2 密钥选项 (Keying Options)
本实现支持标准的 3 密钥选项（Key Option 1），密钥总长度为 192 位（24 字节）：
*   **Option 1 (3 Keys)**：$K1 \ne K2 \ne K3$。这是最安全的模式，有效密钥长度为 168 位（$3 \times 56$）。
*   **Option 2 (2 Keys)**：$K1 \ne K2$ 且 $K3 = K1$。有效密钥长度为 112 位。
*   **Option 3 (1 Key)**：$K1 = K2 = K3$。等同于 DES，有效密钥长度 56 位。

### 2.3 安全性
*   **优点**：相比 DES，安全性大幅提升，足以抵御目前的暴力破解。
*   **缺点**：由于执行了三次 DES，性能是 DES 的 1/3，且 64 位分组长度使其在处理大量数据时仍面临“生日攻击”风险（Sweet32）。目前已被 AES 取代。

### 2.3 支持的模式 (Modes of Operation)
本项目实现了 3DES 的五种标准工作模式：
*   **ECB (Electronic Codebook)**：基础模式，不推荐使用。
*   **CBC (Cipher Block Chaining)**：引入 IV，安全性更高。
*   **CFB (Cipher Feedback)**：流密码模式，支持反馈。
*   **OFB (Output Feedback)**：流密码模式，无错误传播。
*   **CTR (Counter)**：计数器模式，并行性好。

## 3. 魔改建议 (Modification)
*   **独立子密钥生成**：标准 3DES 使用三个独立的 DES 密钥调度。可以魔改为使用一个更长的种子密钥（如 256 位），通过特定的 KDF（密钥派生函数）生成这三个子密钥，简化密钥管理。
*   **混合模式**：中间的“解密”操作本质上是为了兼容 DES。如果是全新设计，可以改为 EEE 模式（三次加密），或者中间层使用不同的置换表。

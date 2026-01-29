#include "crc32.h"

// IEEE 802.3 CRC-32 Polynomial: 0xEDB88320 (Reflected/Reversed representation of 0x04C11DB7)
#define CRC32_POLY 0xEDB88320

static uint32_t crc32_table[256];
static int table_initialized = 0;

void crc32_init(void) {
    uint32_t crc;
    int i, j;

    if (table_initialized) return;

    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc = crc >> 1;
            }
        }
        crc32_table[i] = crc;
    }

    table_initialized = 1;
}

uint32_t crc32(uint32_t crc, const uint8_t *buf, size_t len) {
    if (!table_initialized) {
        crc32_init();
    }

    // 常见的 CRC32 实现中，初始值通常为 0xFFFFFFFF
    // 这里由调用者传入，以便支持分段计算。
    // 如果是第一次调用，调用者应传入 0xFFFFFFFF (或根据协议传入 0)
    // 注意：这里的算法是基于 Table 的 Reflected 实现
    
    // crc = ~crc; // 通常在外部处理或者由调用者传入 ~0

    while (len--) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ *buf++) & 0xFF];
    }

    // return ~crc; // 同样，是否取反由调用者决定或者提供 helper
    return crc;
}

uint32_t crc32_total(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    crc = crc32(crc, buf, len);
    return crc ^ 0xFFFFFFFF;
}

#ifndef _CRC32_H_
#define _CRC32_H_

#include <stdint.h>
#include <stddef.h>

// 初始化 CRC32 表，如果使用动态生成表的方式需要调用一次
void crc32_init(void);

// 计算数据的 CRC32 值
// crc: 初始值，通常为 0xFFFFFFFF (第一次调用) 或 上一次计算的结果 (分段计算)
// buf: 数据缓冲区
// len: 数据长度
// 返回值: 计算后的 CRC32 值 (注意：标准 CRC32 最后通常需要取反，本函数返回的是寄存器的最终值，是否取反取决于具体协议，标准用法是最终结果 ^ 0xFFFFFFFF)
uint32_t crc32(uint32_t crc, const uint8_t *buf, size_t len);

// 辅助函数：一次性计算并返回最终的标准 CRC32 值 (包含初始值设置和结果取反)
uint32_t crc32_total(const uint8_t *buf, size_t len);

#endif // _CRC32_H_

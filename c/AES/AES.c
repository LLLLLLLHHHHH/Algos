#include <string.h> 

#include "AES.h"

/*****************************************************************************/
/* 定义                                                       */
/*****************************************************************************/

// Nb 状态矩阵(State Matrix)的列数 AES的分组长度固定为 128位(16字节), 分组始终映射为4x4字节矩阵, 所以 Nb 恒为 4
#define Nb 4

// Nk 密钥的长度，单位为 32 bit
// Nr 加密轮数。
#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4   
    #define Nr 10    
#endif

/*****************************************************************************/
/* 变量                                                       */
/*****************************************************************************/

// state_t - 用于在解密过程中存储中间结果的数组。
typedef uint8_t state_t[4][4];

static const uint8_t sbox[256] = {
	// 0    1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};


static const uint8_t rsbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};


// 轮常量字数组 Rcon[i] 包含的值由 x 的 (i-1) 次幂给出，其中 x 是有限域 GF(2^8) 中的元素 {02} 的幂。
static const uint8_t Rcon[11] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 
};

/*****************************************************************************/
/* 函数                                                        */
/*****************************************************************************/

static uint8_t getSBoxValue(uint8_t num)
{
  	return sbox[num];
}

// 此函数生成 Nb(Nr+1) 个轮密钥。这些轮密钥在每一轮中用于解密状态。
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
	unsigned i, j, k;
	uint8_t tempa[4]; // 用于列/行操作
	
	// 第一个轮密钥就是密钥本身。
	for (i = 0; i < Nk; ++i)
	{
		RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
		RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
		RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
		RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
	}

	// 所有其他轮密钥都是从之前的轮密钥中生成的。
	for (i = Nk; i < Nb * (Nr + 1); ++i)
	{
		{
			k = (i - 1) * 4;
			tempa[0] = RoundKey[k + 0];
			tempa[1] = RoundKey[k + 1];
			tempa[2] = RoundKey[k + 2];
			tempa[3] = RoundKey[k + 3];
		}

		if (i % Nk == 0)
		{
			// 函数 RotWord()
			// 此函数将一个字中的 4 个字节向左循环移位一次。
			// [a0,a1,a2,a3] 变为 [a1,a2,a3,a0]
			{
				const uint8_t u8tmp = tempa[0];
				tempa[0] = tempa[1];
				tempa[1] = tempa[2];
				tempa[2] = tempa[3];
				tempa[3] = u8tmp;
			}

			// 函数 SubWord()
			// 它接收一个四字节输入字，
			// 并对每个字节应用 S 盒，以产生一个输出字。
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}

			tempa[0] = tempa[0] ^ Rcon[i/Nk];
		}
	#if defined(AES256) && (AES256 == 1)
		if (i % Nk == 4)
		{
			// 函数 SubWord()
			{
				tempa[0] = getSBoxValue(tempa[0]);
				tempa[1] = getSBoxValue(tempa[1]);
				tempa[2] = getSBoxValue(tempa[2]);
				tempa[3] = getSBoxValue(tempa[3]);
			}
		}
	#endif
		j = i * 4; 
		k = (i - Nk) * 4;
		RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
		RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
		RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
		RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	}
}

void AES_init_ctx(AES_ctx* ctx, const uint8_t* key)
{
  	KeyExpansion(ctx->RoundKey, key);
}

void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
	KeyExpansion(ctx->RoundKey, key);
	memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(AES_ctx* ctx, const uint8_t* iv)
{
  	memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}


// 此函数通过 XOR 操作将轮密钥添加到 state 中。
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

// SubBytes 函数将 state 矩阵中的值替换为 S 盒中的值。
static void SubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
		(*state)[j][i] = getSBoxValue((*state)[j][i]);
		}
	}
}

// ShiftRows 函数将状态矩阵中的行向左循环移位。
// 每一行的移位偏移量不同。
// 偏移量 = 行号。因此，第一行不移位。
static void ShiftRows(state_t* state)
{
	uint8_t temp;

	// 将第一行向左循环移位 1 列
	temp           = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;

	// 将第二行向左循环移位 2 列
	temp           = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp           = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// 将第三行向左循环移位 3 列
	temp           = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

// 对一个8位无符号整数 x 进行乘以2的操作，同时处理有限域中的溢出问题
static uint8_t xtime(uint8_t x)
{
  	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// MixColumns 函数对 state 矩阵的列进行混合
static void MixColumns(state_t* state)
{
	uint8_t i;
	uint8_t Tmp, Tm, t;
	for (i = 0; i < 4; ++i)
	{  
		t   = (*state)[i][0];
		Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
		Tm  = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
		Tm  = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
		Tm  = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
		Tm  = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
	}
}

// Multiply 用于在有限域 GF(2^8) 中进行数字乘法。
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  	return (((y & 1) * x) ^
       ((y >> 1 & 1) * xtime(x)) ^
       ((y >> 2 & 1) * xtime(xtime(x))) ^
       ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))); 
}

static uint8_t getSBoxInvert(uint8_t num)
{
  	return rsbox[num];
}

// InvMixColumns 是 MixColumns 的逆操作，用于解密过程。它通过有限域 GF(2^8) 中的乘法和异或操作，将状态矩阵的每一列进行逆向混合。
static void InvMixColumns(state_t* state)
{
	int i;
	uint8_t a, b, c, d;
	for (i = 0; i < 4; ++i)
	{ 
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];

		(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

// InvSubBytes 是 SubBytes 的逆操作，用于解密过程。它通过 S 盒的逆向替换值，将状态矩阵中的每个字节进行逆向替换。
static void InvSubBytes(state_t* state)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
		(*state)[j][i] = getSBoxInvert((*state)[j][i]);
		}
	}
}

// InvShiftRows 是 ShiftRows 的逆操作，用于解密过程。它通过向右循环移位，将状态矩阵的每一行恢复到加密前的状态。
static void InvShiftRows(state_t* state)
{
	uint8_t temp;

	// 将第一行向右循环移位 1 列
	temp = (*state)[3][1];
	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;

	// 将第二行向右循环移位 2 列
	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	// 将第三行向右循环移位 3 列
	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = temp;
}


// 加密函数
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
	uint8_t round = 0;

	// 在开始轮操作之前，将第一轮密钥添加到状态中
	AddRoundKey(0, state, RoundKey);

	// 总共有 Nr 轮。
	// 前 Nr-1 轮是相同的。
	// 这些 Nr 轮在下面的循环中执行。
	// 最后一轮没有 MixColumns()
	for (round = 1; ; ++round)
	{
		SubBytes(state);
		ShiftRows(state);
		if (round == Nr) break;
		MixColumns(state);
		AddRoundKey(round, state, RoundKey);
	}
	// 在最后一轮添加轮密钥
	AddRoundKey(Nr, state, RoundKey);
}

// 解密函数
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
	uint8_t round = 0;

	// 在开始轮操作之前，将最后一轮密钥添加到状态中。
	AddRoundKey(Nr, state, RoundKey);

	// 总共有 Nr 轮。
	// 前 Nr-1 轮是相同的。
	// 这些 Nr 轮在下面的循环中执行。
	// 最后一轮没有 InvMixColumns()
	for (round = (Nr - 1); ; --round)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(round, state, RoundKey);
		if (round == 0) {
		break;
		}
		InvMixColumns(state);
	}
}


void AES_ECB_encrypt_buffer(const AES_ctx* ctx, uint8_t* buf)
{
	Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt_buffer(const AES_ctx* ctx, uint8_t* buf)
{
  	InvCipher((state_t*)buf, ctx->RoundKey);
}


static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
	uint8_t i;
	for (i = 0; i < AES_BLOCKLEN; ++i) // 无论密钥大小如何，块大小始终为 128 位。
	{
		buf[i] ^= Iv[i];
	}
}

void AES_CBC_encrypt_buffer(AES_ctx *ctx, uint8_t* buf, size_t length)
{
	size_t i;
	uint8_t *Iv = ctx->Iv;
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		XorWithIv(buf, Iv);
		Cipher((state_t*)buf, ctx->RoundKey);
		Iv = buf;
		buf += AES_BLOCKLEN;
	}
	// 为下次调用储存 Iv
	memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length)
{
	size_t i;
	uint8_t storeNextIv[AES_BLOCKLEN];
	for (i = 0; i < length; i += AES_BLOCKLEN)
	{
		memcpy(storeNextIv, buf, AES_BLOCKLEN);
		InvCipher((state_t*)buf, ctx->RoundKey);
		XorWithIv(buf, ctx->Iv);
		memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
		buf += AES_BLOCKLEN;
	}
}

// 对称操作：加密和解密使用相同的函数。注意：任何 IV/nonce 都不应与相同的密钥重复使用
void AES_CTR_xcrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length)
{
	uint8_t buffer[AES_BLOCKLEN];
	
	size_t i;
	int bi;
	for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
	{
		if (bi == AES_BLOCKLEN) /* 我们需要重新生成 buffer 中的 XOR 补码 */
		{
			memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
			Cipher((state_t*)buffer, ctx->RoundKey);

			/* 增加 IV 并处理溢出 */
			for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
			{
				/* inc 将会溢出 */
				if (ctx->Iv[bi] == 255)
				{
					ctx->Iv[bi] = 0;
					continue;
				} 
				ctx->Iv[bi] += 1;
				break;   
			}
			bi = 0;
		}

		buf[i] = (buf[i] ^ buffer[bi]);
	}
}

// CFB (Cipher Feedback Mode)
void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length)
{
    size_t i;
    uint8_t* Iv = ctx->Iv;
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        Cipher((state_t*)Iv, ctx->RoundKey);
        XorWithIv(buf, Iv);
        memcpy(Iv, buf, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }
}

void AES_CFB_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length)
{
    size_t i;
    uint8_t storeNextIv[AES_BLOCKLEN];
    uint8_t* Iv = ctx->Iv;
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        memcpy(storeNextIv, buf, AES_BLOCKLEN);
        Cipher((state_t*)Iv, ctx->RoundKey);
        XorWithIv(buf, Iv);
        memcpy(Iv, storeNextIv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }
}

// OFB (Output Feedback Mode)
void AES_OFB_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length)
{
    size_t i;
    uint8_t* Iv = ctx->Iv;
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        Cipher((state_t*)Iv, ctx->RoundKey);
        XorWithIv(buf, Iv);
        buf += AES_BLOCKLEN;
    }
}

// GCM 实现

// GF(2^128) 乘法: r = x * y
// 使用简单的 bitwise shift-and-xor 实现，避免大表，保持 compact。
// 这里的 x, y, r 都是 16 字节大端序。
static void gf128_mul(const uint8_t* x, const uint8_t* y, uint8_t* r)
{
    uint8_t v[16];
    uint8_t z[16];
    int i, j;
    
    // Z_0 = 0
    memset(z, 0, 16);
    // V_0 = Y
    memcpy(v, y, 16);

    for (i = 0; i < 16; ++i) {
        for (j = 7; j >= 0; --j) {
            // 如果 x 的第 i 字节的第 j 位是 1
            if ((x[i] >> j) & 1) {
                // Z = Z ^ V
                int k;
                for (k = 0; k < 16; ++k) z[k] ^= v[k];
            }
            // V = V >> 1 (GF(2^128) 域上)
            // 如果 V 的最低位是 0，则 V = right_shift(V)
            // 如果 V 的最低位是 1，则 V = right_shift(V) ^ R (R = 0xE1...00)
            int lsb = v[15] & 1;
            // Right shift V by 1 bit
            int k;
            uint8_t carry = 0;
            for (k = 0; k < 16; ++k) {
                uint8_t next_carry = v[k] & 1;
                v[k] = (v[k] >> 1) | (carry << 7);
                carry = next_carry;
            }
            if (lsb) {
                // R = 11100001 || 0...0 (in big endian bits, usually represented as 0xE1000... in first byte)
                // 但注意 GCM spec 中位顺序的定义。
                // NIST SP 800-38D: R = 11100001 || 0^120.
                // 对应第一个字节 0xE1.
                v[0] ^= 0xE1;
            }
        }
    }
    memcpy(r, z, 16);
}

// GHASH(H, A, C) = X_{m+n+1}
// 输入: H (subkey), aad, aad_len, ciphertext, cipher_len
// 输出: result (16 bytes)
static void ghash(const uint8_t* h, const uint8_t* aad, size_t aad_len,
                  const uint8_t* cipher, size_t cipher_len, uint8_t* result)
{
    uint8_t y[16];
    uint8_t len_block[16];
    const uint8_t* p;
    size_t left;

    memset(y, 0, 16);

    // 1. Process AAD
    p = aad;
    left = aad_len;
    while (left >= 16) {
        int k;
        for (k = 0; k < 16; ++k) y[k] ^= p[k];
        gf128_mul(y, h, y);
        p += 16;
        left -= 16;
    }
    if (left > 0) {
        int k;
        for (k = 0; k < left; ++k) y[k] ^= p[k];
        gf128_mul(y, h, y);
    }

    // 2. Process Ciphertext
    p = cipher;
    left = cipher_len;
    while (left >= 16) {
        int k;
        for (k = 0; k < 16; ++k) y[k] ^= p[k];
        gf128_mul(y, h, y);
        p += 16;
        left -= 16;
    }
    if (left > 0) {
        int k;
        for (k = 0; k < left; ++k) y[k] ^= p[k];
        gf128_mul(y, h, y);
    }

    // 3. Process Lengths (len(A) || len(C)) in bits (64 bits each)
    // 注意: 大端序存储
    memset(len_block, 0, 16);
    // aad_len * 8
    uint64_t alen_bits = (uint64_t)aad_len * 8;
    uint64_t clen_bits = (uint64_t)cipher_len * 8;
    
    // Store big-endian
    int k;
    for(k=0; k<8; ++k) len_block[k] = (alen_bits >> (56 - 8*k)) & 0xFF;
    for(k=0; k<8; ++k) len_block[8+k] = (clen_bits >> (56 - 8*k)) & 0xFF;

    for (k = 0; k < 16; ++k) y[k] ^= len_block[k];
    gf128_mul(y, h, y);

    memcpy(result, y, 16);
}

// GCM Counter Increment (inc32)
// 仅增加最后 4 字节
static void gcm_inc32(uint8_t* block)
{
    uint32_t val;
    // Load big-endian
    val = (block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15];
    val++;
    // Store big-endian
    block[12] = (val >> 24) & 0xFF;
    block[13] = (val >> 16) & 0xFF;
    block[14] = (val >> 8) & 0xFF;
    block[15] = val & 0xFF;
}

// GCTR(K, ICB, X)
static void gctr(AES_ctx* ctx, const uint8_t* icb, const uint8_t* in, size_t len, uint8_t* out)
{
    uint8_t cb[16];
    uint8_t buf[16];
    size_t i;

    if (len == 0) return;

    memcpy(cb, icb, 16);
    
    size_t n_blocks = len / 16;
    size_t tail = len % 16;

    for (i = 0; i < n_blocks; ++i) {
        // Encrypt CB to get keystream block
        // 注意: Cipher 函数会修改 buf，所以先复制 CB
        memcpy(buf, cb, 16);
        Cipher((state_t*)buf, ctx->RoundKey); // E(K, CB)
        
        // XOR with input
        int k;
        for (k = 0; k < 16; ++k) out[i*16 + k] = in[i*16 + k] ^ buf[k];

        // Increment CB
        gcm_inc32(cb);
    }

    if (tail > 0) {
        memcpy(buf, cb, 16);
        Cipher((state_t*)buf, ctx->RoundKey);
        int k;
        for (k = 0; k < tail; ++k) out[n_blocks*16 + k] = in[n_blocks*16 + k] ^ buf[k];
    }
}

void AES_GCM_encrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     uint8_t* tag, size_t tag_len)
{
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t s[16];
    uint8_t zero[16] = {0};

    // 1. Calculate H = E(K, 0^128)
    memcpy(h, zero, 16);
    Cipher((state_t*)h, ctx->RoundKey);

    // 2. Calculate J0
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        // GHASH(H, {}, IV)
        // Pad IV to 128-bit boundary, then len(IV)
        // 这里我们可以复用 ghash 函数，将 IV 当作 Ciphertext 部分传入 (AAD 为空)
        // GHASH(H, AAD, C) 计算的是 AAD || Pad || C || Pad || len(A) || len(C)
        // 但对于 J0 的计算，spec 是 GHASH_H(IV || 0... || len(IV)_64)
        // 这实际上等同于调用 ghash(h, NULL, 0, iv, iv_len, j0)
        ghash(h, NULL, 0, iv, iv_len, j0);
    }

    // 3. GCTR Encryption: C = GCTR(K, inc32(J0), P)
    // First increment J0 to get the initial counter for data
    uint8_t j1[16];
    memcpy(j1, j0, 16);
    gcm_inc32(j1);
    
    gctr(ctx, j1, input, length, output);

    // 4. Calculate S = GHASH(H, AAD, C)
    ghash(h, aad, aad_len, output, length, s);

    // 5. Generate Tag: T = MSB_t(GCTR(K, J0, S))
    // GCTR(K, J0, S) = S XOR E(K, J0)
    // 先计算 E(K, J0)
    uint8_t e_j0[16];
    memcpy(e_j0, j0, 16);
    Cipher((state_t*)e_j0, ctx->RoundKey);
    
    int k;
    for (k = 0; k < tag_len && k < 16; ++k) {
        tag[k] = s[k] ^ e_j0[k];
    }
}

int AES_GCM_decrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     const uint8_t* tag, size_t tag_len)
{
    uint8_t h[16];
    uint8_t j0[16];
    uint8_t s[16];
    uint8_t calc_tag[16];
    uint8_t zero[16] = {0};

    // 1. Calculate H
    memcpy(h, zero, 16);
    Cipher((state_t*)h, ctx->RoundKey);

    // 2. Calculate J0
    if (iv_len == 12) {
        memcpy(j0, iv, 12);
        j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    } else {
        ghash(h, NULL, 0, iv, iv_len, j0);
    }

    // 3. Calculate S = GHASH(H, AAD, C) -> C is input here
    // Calculate tag from Ciphertext BEFORE decrypting (crucial for in-place decryption)
    ghash(h, aad, aad_len, input, length, s);

    // 4. Calculate Tag
    uint8_t e_j0[16];
    memcpy(e_j0, j0, 16);
    Cipher((state_t*)e_j0, ctx->RoundKey);

    int k;
    int diff = 0;
    for (k = 0; k < tag_len && k < 16; ++k) {
        calc_tag[k] = s[k] ^ e_j0[k];
        diff |= (calc_tag[k] ^ tag[k]);
    }

    // If tag check fails, we should ideally not output plaintext.
    // But for this API, we return status.
    if (diff != 0) {
        return 1;
    }

    // 5. GCTR Decryption: P = GCTR(K, inc32(J0), C)
    uint8_t j1[16];
    memcpy(j1, j0, 16);
    gcm_inc32(j1);

    gctr(ctx, j1, input, length, output);

    return 0;
}

// CCM Implementation

// Helper to format the first block B0 for CBC-MAC
// Flags: Reserved(1) | Adata(1) | (t-2)/2 (3) | (q-1) (3)
static void ccm_format_b0(uint8_t* b0, const uint8_t* nonce, size_t nonce_len, size_t adata_len, size_t payload_len, size_t tag_len)
{
    uint8_t q = 15 - (uint8_t)nonce_len; // q = 15 - n
    uint8_t t = (uint8_t)tag_len;
    uint8_t flags = 0;

    // Adata present?
    if (adata_len > 0) flags |= 0x40;
    
    // Encode t: (t-2)/2
    flags |= ((t - 2) / 2) << 3;

    // Encode q: (q-1)
    flags |= (q - 1);

    b0[0] = flags;

    // Nonce
    memcpy(b0 + 1, nonce, nonce_len);

    // Q: Message length in big-endian, q bytes
    size_t i;
    for (i = 0; i < q; ++i) {
        b0[15 - i] = (payload_len >> (8 * i)) & 0xFF;
    }
}

// Helper to format the counter block Ctr0
// Flags: Reserved(1) | Reserved(1) | 0(3) | (q-1) (3)
static void ccm_format_ctr0(uint8_t* ctr0, const uint8_t* nonce, size_t nonce_len)
{
    uint8_t q = 15 - (uint8_t)nonce_len;
    uint8_t flags = (q - 1);

    ctr0[0] = flags;
    memcpy(ctr0 + 1, nonce, nonce_len);
    // Counter starts at 0 (for Ctr0) or 1 (for first block)
    // Initialize rest to 0
    size_t i;
    for (i = 0; i < q; ++i) {
        ctr0[15 - i] = 0;
    }
}

static void ccm_inc_ctr(uint8_t* ctr, size_t q)
{
    size_t i;
    for (i = 0; i < q; ++i) {
        ctr[15 - i]++;
        if (ctr[15 - i] != 0) break;
    }
}

void AES_CCM_encrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     uint8_t* tag, size_t tag_len)
{
    uint8_t b[16];
    uint8_t y[16] = {0};
    uint8_t ctr[16];
    uint8_t s0[16];
    size_t i;

    // 1. Calculate MAC (CBC-MAC)
    // B0
    memset(b, 0, 16);
    ccm_format_b0(b, iv, iv_len, aad_len, length, tag_len);
    
    // Y0 = E(K, B0)
    for (i = 0; i < 16; ++i) y[i] ^= b[i];
    Cipher((state_t*)y, ctx->RoundKey);

    // Process AAD
    if (aad_len > 0) {
        // ... (Header logic)
        
        // Re-implement AAD loop cleanly
        size_t total_aad_bytes = (aad_len < 0xFF00) ? 2 + aad_len : 6 + aad_len;
        size_t processed = 0;
        
        uint8_t header[6];
        size_t header_len = 0;
        if (aad_len < 0xFF00) {
            header[0] = (aad_len >> 8) & 0xFF;
            header[1] = aad_len & 0xFF;
            header_len = 2;
        } else {
            header[0] = 0xFF; header[1] = 0xFE;
            header[2] = (aad_len >> 24) & 0xFF; header[3] = (aad_len >> 16) & 0xFF;
            header[4] = (aad_len >> 8) & 0xFF; header[5] = aad_len & 0xFF;
            header_len = 6;
        }

        size_t h_idx = 0;
        size_t a_idx = 0;
        
        while (processed < total_aad_bytes) {
             for (i = 0; i < 16; ++i) {
                 uint8_t byte = 0;
                 if (h_idx < header_len) {
                     byte = header[h_idx++];
                 } else if (a_idx < aad_len) {
                     byte = aad[a_idx++];
                 }
                 // padding is 0, implicit
                 
                 y[i] ^= byte;
                 processed++;
                 if (processed == total_aad_bytes) break;
             }
             Cipher((state_t*)y, ctx->RoundKey);
             // if (processed == total_aad_bytes) break; // This break is not needed here as the while condition handles it, but we need to ensure we don't Cipher again if we finished exactly on block boundary?
             // Actually, CBC-MAC processes full blocks.
             // If we filled a partial block and finished (processed == total_aad_bytes), we just did Cipher() on the padded block. Correct.
             // If we filled a full block and have more, we Cipher() and continue.
             // If we filled a full block and finished, we Cipher() and stop.
             // The loop structure:
             // Fill buffer (Y ^= data)
             // If buffer full or end of data: Cipher(Y)
             
             // The current logic:
             // Inner loop xors up to 16 bytes.
             // If we hit end of data inside inner loop, we break inner loop.
             // Then we Cipher(Y). This is correct for the last partial block (padded with 0s because we didn't touch y[i] for i > end).
             // BUT, if we finished exactly at 16 bytes, we Cipher(Y) and then outer loop terminates. Correct.
        }
    }

    // Process Payload (Plaintext) for MAC
    size_t p_idx = 0;
    while (p_idx < length) {
        for (i = 0; i < 16; ++i) {
            if (p_idx < length) {
                y[i] ^= input[p_idx++];
            } else {
                y[i] ^= 0; // Padding
            }
        }
        Cipher((state_t*)y, ctx->RoundKey);
    }
    
    // Tag T = MSB_t(Y_m)
    // But we need to XOR with S0 = E(K, Ctr0)
    
    // 2. Generate Key Stream and Encrypt
    // Ctr0
    ccm_format_ctr0(ctr, iv, iv_len);
    
    // S0 = E(K, Ctr0)
    memcpy(s0, ctr, 16);
    Cipher((state_t*)s0, ctx->RoundKey);
    
    // Encrypt Payload: CTR mode starting with Ctr1
    uint8_t q = 15 - (uint8_t)iv_len;
    uint8_t keystream[16];
    
    p_idx = 0;
    while (p_idx < length) {
        ccm_inc_ctr(ctr, q); // Ctr++
        memcpy(keystream, ctr, 16);
        Cipher((state_t*)keystream, ctx->RoundKey);
        
        for (i = 0; i < 16 && p_idx < length; ++i) {
            output[p_idx] = input[p_idx] ^ keystream[i];
            p_idx++;
        }
    }

    // 3. Finalize Tag
    for (i = 0; i < tag_len; ++i) {
        tag[i] = y[i] ^ s0[i];
    }
}

int AES_CCM_decrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     const uint8_t* tag, size_t tag_len)
{
    uint8_t ctr[16];
    uint8_t s0[16];
    uint8_t y[16] = {0};
    uint8_t b[16];
    size_t i;

    // 1. Decrypt Payload first (CTR mode)
    ccm_format_ctr0(ctr, iv, iv_len);
    
    // S0
    memcpy(s0, ctr, 16);
    Cipher((state_t*)s0, ctx->RoundKey);
    
    uint8_t q = 15 - (uint8_t)iv_len;
    uint8_t keystream[16];
    size_t p_idx = 0;
    
    while (p_idx < length) {
        ccm_inc_ctr(ctr, q);
        memcpy(keystream, ctr, 16);
        Cipher((state_t*)keystream, ctx->RoundKey);
        
        for (i = 0; i < 16 && p_idx < length; ++i) {
            output[p_idx] = input[p_idx] ^ keystream[i];
            p_idx++;
        }
    }

    // 2. Re-calculate MAC from Decrypted Payload (output) + AAD
    // B0
    memset(b, 0, 16);
    ccm_format_b0(b, iv, iv_len, aad_len, length, tag_len);
    
    for (i = 0; i < 16; ++i) y[i] ^= b[i];
    Cipher((state_t*)y, ctx->RoundKey);

    // Process AAD
    if (aad_len > 0) {
        size_t total_aad_bytes = (aad_len < 0xFF00) ? 2 + aad_len : 6 + aad_len;
        size_t processed = 0;
        
        uint8_t header[6];
        size_t header_len = 0;
        if (aad_len < 0xFF00) {
            header[0] = (aad_len >> 8) & 0xFF;
            header[1] = aad_len & 0xFF;
            header_len = 2;
        } else {
            header[0] = 0xFF; header[1] = 0xFE;
            header[2] = (aad_len >> 24) & 0xFF; header[3] = (aad_len >> 16) & 0xFF;
            header[4] = (aad_len >> 8) & 0xFF; header[5] = aad_len & 0xFF;
            header_len = 6;
        }

        size_t h_idx = 0;
        size_t a_idx = 0;
        
        while (processed < total_aad_bytes) {
             for (i = 0; i < 16; ++i) {
                 uint8_t byte = 0;
                 if (h_idx < header_len) {
                     byte = header[h_idx++];
                 } else if (a_idx < aad_len) {
                     byte = aad[a_idx++];
                 }
                 y[i] ^= byte;
                 processed++;
                 if (processed == total_aad_bytes) break;
             }
             Cipher((state_t*)y, ctx->RoundKey);
             if (processed == total_aad_bytes) break;
        }
    }

    // Process Payload (Plaintext - which is now in 'output')
    p_idx = 0;
    while (p_idx < length) {
        for (i = 0; i < 16; ++i) {
            if (p_idx < length) {
                y[i] ^= output[p_idx++];
            } else {
                y[i] ^= 0;
            }
        }
        Cipher((state_t*)y, ctx->RoundKey);
    }

    // 3. Verify Tag
    uint8_t calc_tag[16];
    for (i = 0; i < tag_len; ++i) {
        calc_tag[i] = y[i] ^ s0[i];
    }
    
    // Compare
    int diff = 0;
    for (i = 0; i < tag_len; ++i) {
        diff |= (calc_tag[i] ^ tag[i]);
    }

    return (diff == 0) ? 0 : 1;
}

// EAX Implementation

static void gf128_double(uint8_t* in, uint8_t* out)
{
    int i;
    uint8_t msb = in[0] & 0x80;
    
    // Shift left
    for (i = 0; i < 15; ++i) {
        out[i] = (in[i] << 1) | ((in[i+1] >> 7) & 1);
    }
    out[15] = (in[15] << 1);
    
    if (msb) {
        out[15] ^= 0x87;
    }
}

static void cmac_generate_subkeys(AES_ctx* ctx, uint8_t* k1, uint8_t* k2)
{
    uint8_t L[16] = {0};
    
    // L = E(K, 0)
    Cipher((state_t*)L, ctx->RoundKey);
    
    // K1 = 2 * L
    gf128_double(L, k1);
    
    // K2 = 2 * K1
    gf128_double(k1, k2);
}

static void cmac_compute(AES_ctx* ctx, const uint8_t* k1, const uint8_t* k2, 
                         uint8_t tweak, const uint8_t* input, size_t length, uint8_t* out)
{
    uint8_t y[16] = {0};
    uint8_t block[16];
    size_t i;
    
    // Process tweak block [t]_n
    // [t]_n = 0...0 || t (16 bytes)
    memset(block, 0, 16);
    block[15] = tweak;
    
    // Y = E(K, block)
    memcpy(y, block, 16);
    Cipher((state_t*)y, ctx->RoundKey);
    
    // Process input
    const uint8_t* p = input;
    size_t left = length;
    
    if (length == 0) {
        // Empty message: 10^128 ^ K2
        memset(block, 0, 16);
        block[0] = 0x80;
        for(i=0; i<16; ++i) block[i] ^= k2[i];
        for(i=0; i<16; ++i) y[i] ^= block[i];
        Cipher((state_t*)y, ctx->RoundKey);
    } else {
        while (left > 16) {
            for(i=0; i<16; ++i) y[i] ^= p[i];
            Cipher((state_t*)y, ctx->RoundKey);
            p += 16;
            left -= 16;
        }
        
        memset(block, 0, 16);
        memcpy(block, p, left);
        
        if (left == 16) {
            // Full block ^ K1
            for(i=0; i<16; ++i) block[i] ^= k1[i];
        } else {
            // Partial block + Padding ^ K2
            block[left] = 0x80;
            for(i=0; i<16; ++i) block[i] ^= k2[i];
        }
        
        for(i=0; i<16; ++i) y[i] ^= block[i];
        Cipher((state_t*)y, ctx->RoundKey);
    }
    
    memcpy(out, y, 16);
}

void AES_EAX_encrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* header, size_t header_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     uint8_t* tag, size_t tag_len)
{
    uint8_t k1[16], k2[16];
    uint8_t n_tag[16], h_tag[16], c_tag[16];
    uint8_t full_tag[16];
    int i;

    // 1. Generate CMAC Subkeys
    cmac_generate_subkeys(ctx, k1, k2);

    // 2. N_tag = CMAC(0, Nonce)
    cmac_compute(ctx, k1, k2, 0, iv, iv_len, n_tag);

    // 3. H_tag = CMAC(1, Header)
    cmac_compute(ctx, k1, k2, 1, header, header_len, h_tag);

    // 4. CTR Encryption
    // Use N_tag as IV for CTR
    AES_ctx_set_iv(ctx, n_tag);
    
    // CTR encrypt input -> output
    // Note: input and output can overlap if handled carefully, 
    // but AES_CTR_xcrypt_buffer works in-place if buf is provided.
    // Here we have input and output separate.
    // Copy input to output then encrypt in-place.
    memcpy(output, input, length);
    AES_CTR_xcrypt_buffer(ctx, output, length);

    // 5. C_tag = CMAC(2, Ciphertext)
    cmac_compute(ctx, k1, k2, 2, output, length, c_tag);

    // 6. Tag = N_tag ^ H_tag ^ C_tag
    for (i = 0; i < 16; ++i) {
        full_tag[i] = n_tag[i] ^ h_tag[i] ^ c_tag[i];
    }

    // Output tag
    memcpy(tag, full_tag, tag_len < 16 ? tag_len : 16);
}

int AES_EAX_decrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* header, size_t header_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     const uint8_t* tag, size_t tag_len)
{
    uint8_t k1[16], k2[16];
    uint8_t n_tag[16], h_tag[16], c_tag[16];
    uint8_t full_tag[16];
    int i;

    // 1. Generate Subkeys
    cmac_generate_subkeys(ctx, k1, k2);

    // 2. N_tag = CMAC(0, Nonce)
    cmac_compute(ctx, k1, k2, 0, iv, iv_len, n_tag);

    // 3. H_tag = CMAC(1, Header)
    cmac_compute(ctx, k1, k2, 1, header, header_len, h_tag);

    // 4. C_tag = CMAC(2, Ciphertext)
    // Input is Ciphertext
    cmac_compute(ctx, k1, k2, 2, input, length, c_tag);

    // 5. Calculate Tag
    for (i = 0; i < 16; ++i) {
        full_tag[i] = n_tag[i] ^ h_tag[i] ^ c_tag[i];
    }

    // 6. Verify Tag
    int diff = 0;
    for (i = 0; i < tag_len && i < 16; ++i) {
        diff |= (tag[i] ^ full_tag[i]);
    }

    if (diff != 0) return 1; // Auth failed

    // 7. Decrypt
    // Use N_tag as IV
    AES_ctx_set_iv(ctx, n_tag);
    memcpy(output, input, length);
    AES_CTR_xcrypt_buffer(ctx, output, length);

    return 0;
}


// -----------------------------------------------------------------------------
// OCB (RFC 7253 / OCB3) Implementation (bytestring-oriented)
// -----------------------------------------------------------------------------

static void aes_encrypt_block(const AES_ctx* ctx, const uint8_t in[16], uint8_t out[16])
{
    memcpy(out, in, 16);
    Cipher((state_t*)out, ctx->RoundKey);
}

static void aes_decrypt_block(const AES_ctx* ctx, const uint8_t in[16], uint8_t out[16])
{
    memcpy(out, in, 16);
    InvCipher((state_t*)out, ctx->RoundKey);
}

static void xor_block(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])
{
    int i;
    for (i = 0; i < 16; ++i) out[i] = a[i] ^ b[i];
}

static void xor_block_inplace(uint8_t a[16], const uint8_t b[16])
{
    int i;
    for (i = 0; i < 16; ++i) a[i] ^= b[i];
}

static unsigned ntz_size_t(size_t x)
{
    // x is always >= 1 in OCB loops
    unsigned n = 0;
    while ((x & 1u) == 0u) {
        n++;
        x >>= 1;
    }
    return n;
}

// Extract Offset_0 = Stretch[1+bottom..128+bottom] for bottom in [0,63]
// Stretch is 24 bytes: Ktop (16) || (Ktop[0..7] xor Ktop[1..8]) (8)
static void ocb_offset_from_stretch(const uint8_t stretch[24], unsigned bottom, uint8_t offset0[16])
{
    unsigned byte_shift = bottom / 8;
    unsigned bit_shift = bottom % 8;
    unsigned i;

    if (bit_shift == 0) {
        for (i = 0; i < 16; ++i) offset0[i] = stretch[byte_shift + i];
        return;
    }

    for (i = 0; i < 16; ++i) {
        uint8_t a = stretch[byte_shift + i];
        uint8_t b = stretch[byte_shift + i + 1];
        offset0[i] = (uint8_t)((a << bit_shift) | (b >> (8 - bit_shift)));
    }
}

// double() in GF(2^128) as defined by RFC 7253: shift-left, xor 0x87 if msb was set
static void ocb_double_128(const uint8_t in[16], uint8_t out[16])
{
    gf128_double((uint8_t*)in, out);
}

static void ocb_build_L(const AES_ctx* ctx, uint8_t L_star[16], uint8_t L_dollar[16], uint8_t L_table[64][16], unsigned* L_max)
{
    uint8_t zero[16] = {0};

    // L_* = ENCIPHER(K, 0^128)
    aes_encrypt_block(ctx, zero, L_star);
    // L_$ = double(L_*)
    ocb_double_128(L_star, L_dollar);
    // L_0 = double(L_$)
    ocb_double_128(L_dollar, L_table[0]);
    *L_max = 0;
}

static const uint8_t* ocb_get_L(uint8_t L_table[64][16], unsigned* L_max, unsigned idx)
{
    // idx is ntz(i), so bounded by log2(block_count). We cap at 63.
    while (*L_max < idx) {
        unsigned next = *L_max + 1;
        if (next >= 64) break;
        ocb_double_128(L_table[*L_max], L_table[next]);
        *L_max = next;
    }
    return L_table[idx];
}

static void ocb_hash(const AES_ctx* ctx,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t L_star[16], uint8_t L_table[64][16], unsigned* L_max,
                     uint8_t out_sum[16])
{
    uint8_t sum[16] = {0};
    uint8_t offset[16] = {0};
    uint8_t tmp[16];
    uint8_t enc[16];

    size_t m = aad_len / 16;
    size_t rem = aad_len % 16;

    size_t i;
    for (i = 1; i <= m; ++i) {
        const uint8_t* Li = ocb_get_L(L_table, L_max, ntz_size_t(i));
        xor_block_inplace(offset, Li);

        xor_block(tmp, aad + (i - 1) * 16, offset);
        aes_encrypt_block(ctx, tmp, enc);
        xor_block_inplace(sum, enc);
    }

    if (rem > 0) {
        xor_block_inplace(offset, L_star);
        memset(tmp, 0, 16);
        memcpy(tmp, aad + m * 16, rem);
        tmp[rem] = 0x80; // A_* || 1 || zeros(...)
        xor_block_inplace(tmp, offset);
        aes_encrypt_block(ctx, tmp, enc);
        xor_block_inplace(sum, enc);
    }

    memcpy(out_sum, sum, 16);
}

static void ocb_format_nonce(uint8_t nonce_block[16], const uint8_t* nonce, size_t nonce_len, size_t tag_len)
{
    // Implements:
    // Nonce = num2str(TAGLEN mod 128,7) || zeros(120-bitlen(N)) || 1 || N
    // This implementation assumes N is a bytestring (nonce_len bytes), 1..15.
    memset(nonce_block, 0, 16);

    uint8_t tag_bits_mod_128 = (uint8_t)((tag_len * 8) % 128);
    nonce_block[0] = (uint8_t)((tag_bits_mod_128 << 1) & 0xFE); // top 7 bits

    // Place N at the end
    if (nonce_len > 0) {
        memcpy(nonce_block + (16 - nonce_len), nonce, nonce_len);
    }

    // Set the separator '1' bit immediately before N
    // For bytestring N: bit position is 128 - 8*nonce_len, which is the LSB of byte (15 - nonce_len).
    nonce_block[15 - nonce_len] |= 0x01;
}

static int ct_memcmp_n(const uint8_t* a, const uint8_t* b, size_t n)
{
    size_t i;
    uint8_t diff = 0;
    for (i = 0; i < n; ++i) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff; // 0 if equal
}

void AES_OCB_encrypt(AES_ctx* ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     uint8_t* tag, size_t tag_len)
{
    // Restrict to RFC5116-style bounds: nonce_len 1..15, tag_len 1..16
    if (nonce_len < 1 || nonce_len > 15 || tag_len < 1 || tag_len > 16) {
        // Invalid parameters; best-effort: zero outputs
        if (tag && tag_len) memset(tag, 0, tag_len);
        if (output && input && length) memcpy(output, input, length);
        return;
    }

    uint8_t L_star[16], L_dollar[16];
    uint8_t L_table[64][16];
    unsigned L_max = 0;
    ocb_build_L(ctx, L_star, L_dollar, L_table, &L_max);

    // Nonce processing
    uint8_t nb[16];
    ocb_format_nonce(nb, nonce, nonce_len, tag_len);
    unsigned bottom = (unsigned)(nb[15] & 0x3F);

    uint8_t nb_ktop[16];
    memcpy(nb_ktop, nb, 16);
    nb_ktop[15] &= 0xC0; // zeros(6)

    uint8_t Ktop[16];
    aes_encrypt_block(ctx, nb_ktop, Ktop);

    uint8_t stretch[24];
    memcpy(stretch, Ktop, 16);
    int i;
    for (i = 0; i < 8; ++i) stretch[16 + i] = (uint8_t)(Ktop[i] ^ Ktop[i + 1]);

    uint8_t offset[16];
    ocb_offset_from_stretch(stretch, bottom, offset);

    uint8_t checksum[16] = {0};

    size_t m = length / 16;
    size_t rem = length % 16;

    uint8_t tmp[16];
    uint8_t enc[16];

    size_t blk;
    for (blk = 1; blk <= m; ++blk) {
        const uint8_t* Li = ocb_get_L(L_table, &L_max, ntz_size_t(blk));
        xor_block_inplace(offset, Li);

        const uint8_t* P = input + (blk - 1) * 16;
        uint8_t* C = output + (blk - 1) * 16;

        xor_block(tmp, P, offset);
        aes_encrypt_block(ctx, tmp, enc);
        xor_block(tmp, enc, offset); // tmp = C_i
        memcpy(C, tmp, 16);

        xor_block_inplace(checksum, P);
    }

    uint8_t tag_full[16];
    uint8_t hash_sum[16];

    if (rem > 0) {
        // Offset_* = Offset_m xor L_*
        xor_block_inplace(offset, L_star);

        uint8_t pad[16];
        aes_encrypt_block(ctx, offset, pad);

        const uint8_t* Pstar = input + m * 16;
        uint8_t* Cstar = output + m * 16;
        for (i = 0; i < (int)rem; ++i) Cstar[i] = (uint8_t)(Pstar[i] ^ pad[i]);

        // Checksum_* = Checksum_m xor (P_* || 1 || zeros(...))
        memset(tmp, 0, 16);
        memcpy(tmp, Pstar, rem);
        tmp[rem] = 0x80;
        xor_block_inplace(checksum, tmp);

        // Tag = ENCIPHER(K, Checksum_* xor Offset_* xor L_$) xor HASH(K,A)
        xor_block(tmp, checksum, offset);
        xor_block_inplace(tmp, L_dollar);
        aes_encrypt_block(ctx, tmp, tag_full);
    } else {
        // Tag = ENCIPHER(K, Checksum_m xor Offset_m xor L_$) xor HASH(K,A)
        xor_block(tmp, checksum, offset);
        xor_block_inplace(tmp, L_dollar);
        aes_encrypt_block(ctx, tmp, tag_full);
    }

    ocb_hash(ctx, aad, aad_len, L_star, L_table, &L_max, hash_sum);
    xor_block_inplace(tag_full, hash_sum);

    memcpy(tag, tag_full, tag_len);
}

int AES_OCB_decrypt(AES_ctx* ctx,
                    const uint8_t* nonce, size_t nonce_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* input, uint8_t* output, size_t length,
                    const uint8_t* tag, size_t tag_len)
{
    if (nonce_len < 1 || nonce_len > 15 || tag_len < 1 || tag_len > 16) {
        return 1;
    }

    uint8_t L_star[16], L_dollar[16];
    uint8_t L_table[64][16];
    unsigned L_max = 0;
    ocb_build_L(ctx, L_star, L_dollar, L_table, &L_max);

    // Nonce processing
    uint8_t nb[16];
    ocb_format_nonce(nb, nonce, nonce_len, tag_len);
    unsigned bottom = (unsigned)(nb[15] & 0x3F);

    uint8_t nb_ktop[16];
    memcpy(nb_ktop, nb, 16);
    nb_ktop[15] &= 0xC0;

    uint8_t Ktop[16];
    aes_encrypt_block(ctx, nb_ktop, Ktop);

    uint8_t stretch[24];
    memcpy(stretch, Ktop, 16);
    int i;
    for (i = 0; i < 8; ++i) stretch[16 + i] = (uint8_t)(Ktop[i] ^ Ktop[i + 1]);

    uint8_t offset[16];
    ocb_offset_from_stretch(stretch, bottom, offset);

    uint8_t checksum[16] = {0};

    size_t m = length / 16;
    size_t rem = length % 16;

    uint8_t tmp[16];
    uint8_t dec[16];

    size_t blk;
    for (blk = 1; blk <= m; ++blk) {
        const uint8_t* Li = ocb_get_L(L_table, &L_max, ntz_size_t(blk));
        xor_block_inplace(offset, Li);

        const uint8_t* C = input + (blk - 1) * 16;
        uint8_t* P = output + (blk - 1) * 16;

        xor_block(tmp, C, offset);
        aes_decrypt_block(ctx, tmp, dec);
        xor_block(tmp, dec, offset); // tmp = P_i
        memcpy(P, tmp, 16);

        xor_block_inplace(checksum, tmp);
    }

    uint8_t tag_full[16];
    uint8_t hash_sum[16];

    if (rem > 0) {
        xor_block_inplace(offset, L_star);

        uint8_t pad[16];
        aes_encrypt_block(ctx, offset, pad);

        const uint8_t* Cstar = input + m * 16;
        uint8_t* Pstar = output + m * 16;
        for (i = 0; i < (int)rem; ++i) Pstar[i] = (uint8_t)(Cstar[i] ^ pad[i]);

        memset(tmp, 0, 16);
        memcpy(tmp, Pstar, rem);
        tmp[rem] = 0x80;
        xor_block_inplace(checksum, tmp);

        xor_block(tmp, checksum, offset);
        xor_block_inplace(tmp, L_dollar);
        aes_encrypt_block(ctx, tmp, tag_full);
    } else {
        xor_block(tmp, checksum, offset);
        xor_block_inplace(tmp, L_dollar);
        aes_encrypt_block(ctx, tmp, tag_full);
    }

    ocb_hash(ctx, aad, aad_len, L_star, L_table, &L_max, hash_sum);
    xor_block_inplace(tag_full, hash_sum);

    // Verify tag (constant-time)
    if (ct_memcmp_n(tag_full, tag, tag_len) != 0) {
        return 1;
    }
    return 0;
}



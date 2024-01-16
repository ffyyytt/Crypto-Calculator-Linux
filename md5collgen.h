#include <sstream>
#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include "md5.h"

// https://github.com/zhijieshi/md5collgen/tree/master

const uint32 MD5IV[] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
void md5collgen(std::string& prefixfn, std::string& outfn1, std::string& outfn2, std::string& ihv);

void md5_compress(uint32 ihv[], const uint32 block[]);

void find_block0(uint32 block[], const uint32 IV[]);
void find_block1(uint32 block[], const uint32 IV[]);

void find_block1_wang(uint32 block[], const uint32 IV[]);
void find_block1_stevens_11(uint32 block[], const uint32 IV[]);
void find_block1_stevens_10(uint32 block[], const uint32 IV[]);
void find_block1_stevens_01(uint32 block[], const uint32 IV[]);
void find_block1_stevens_00(uint32 block[], const uint32 IV[]);


extern uint32 seed32_1, seed32_2;
inline uint32 xrng64()
{
	uint32 t = seed32_1 ^ (seed32_1 << 10);
	seed32_1 = seed32_2;
	seed32_2 = (seed32_2 ^ (seed32_2 >> 10)) ^ (t ^ (t >> 13));
	return seed32_1;
}

inline uint32 FF(uint32 b, uint32 c, uint32 d)
{
	return d ^ (b & (c ^ d));
}
inline uint32 GG(uint32 b, uint32 c, uint32 d)
{
	return c ^ (d & (b ^ c));
}
inline uint32 HH(uint32 b, uint32 c, uint32 d)
{
	return b ^ c ^ d;
}
inline uint32 II(uint32 b, uint32 c, uint32 d)
{
	return c ^ (b | ~d);
}
inline uint32 RL(uint32 x, unsigned int n)
{
	return (x << n) | (x >> (32 - n));
}
inline uint32 RR(uint32 x, unsigned int n)
{
	return (x >> n) | (x << (32 - n));
}

#define MD5_STEP(f, a, b, c, d, m, ac, rc) ( \
	a += f(b, c, d) + m + ac, \
	a = (a<<rc | a>>(32-rc)) + b )
#define MD5_REVERSE_STEP(t,AC,RC) (	\
	block[t] = Q[Qoff + t + 1] - Q[Qoff + t], \
	block[t] = RR(block[t], RC) - FF(Q[Qoff + t], Q[Qoff + t - 1], Q[Qoff + t - 2]) - Q[Qoff + t - 3] - AC )

#define Qoff 3
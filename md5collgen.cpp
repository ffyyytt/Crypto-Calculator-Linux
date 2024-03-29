#include "md5collgen.h"

uint32 seed32_1, seed32_2;

void find_block0(uint32 block[], const uint32 IV[])
{
	uint32 Q[68] = { IV[0], IV[3], IV[2], IV[1] };

	std::vector<uint32> q4mask(1 << 4);
	for (unsigned k = 0; k < q4mask.size(); ++k)
		q4mask[k] = ((k << 2) ^ (k << 26)) & 0x38000004;

	std::vector<uint32> q9q10mask(1 << 3);
	for (unsigned k = 0; k < q9q10mask.size(); ++k)
		q9q10mask[k] = ((k << 13) ^ (k << 4)) & 0x2060;

	std::vector<uint32> q9mask(1 << 16);
	for (unsigned k = 0; k < q9mask.size(); ++k)
		q9mask[k] = ((k << 1) ^ (k << 2) ^ (k << 5) ^ (k << 7) ^ (k << 8) ^ (k << 10) ^ (k << 11) ^ (k << 13)) & 0x0eb94f16;

	while (true)
	{
		Q[Qoff + 1] = xrng64();
		Q[Qoff + 3] = (xrng64() & 0xfe87bc3f) | 0x017841c0;
		Q[Qoff + 4] = (xrng64() & 0x44000033) | 0x000002c0 | (Q[Qoff + 3] & 0x0287bc00);
		Q[Qoff + 5] = 0x41ffffc8 | (Q[Qoff + 4] & 0x04000033);
		Q[Qoff + 6] = 0xb84b82d6;
		Q[Qoff + 7] = (xrng64() & 0x68000084) | 0x02401b43;
		Q[Qoff + 8] = (xrng64() & 0x2b8f6e04) | 0x005090d3 | (~Q[Qoff + 7] & 0x40000000);
		Q[Qoff + 9] = 0x20040068 | (Q[Qoff + 8] & 0x00020000) | (~Q[Qoff + 8] & 0x40000000);
		Q[Qoff + 10] = (xrng64() & 0x40000000) | 0x1040b089;
		Q[Qoff + 11] = (xrng64() & 0x10408008) | 0x0fbb7f16 | (~Q[Qoff + 10] & 0x40000000);
		Q[Qoff + 12] = (xrng64() & 0x1ed9df7f) | 0x00022080 | (~Q[Qoff + 11] & 0x40200000);
		Q[Qoff + 13] = (xrng64() & 0x5efb4f77) | 0x20049008;
		Q[Qoff + 14] = (xrng64() & 0x1fff5f77) | 0x0000a088 | (~Q[Qoff + 13] & 0x40000000);
		Q[Qoff + 15] = (xrng64() & 0x5efe7ff7) | 0x80008000 | (~Q[Qoff + 14] & 0x00010000);
		Q[Qoff + 16] = (xrng64() & 0x1ffdffff) | 0xa0000000 | (~Q[Qoff + 15] & 0x40020000);

		MD5_REVERSE_STEP(0, 0xd76aa478, 7);
		MD5_REVERSE_STEP(6, 0xa8304613, 17);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);
		MD5_REVERSE_STEP(11, 0x895cd7be, 22);
		MD5_REVERSE_STEP(14, 0xa679438e, 17);
		MD5_REVERSE_STEP(15, 0x49b40821, 22);

		const uint32 tt1 = FF(Q[Qoff + 1], Q[Qoff + 0], Q[Qoff - 1]) + Q[Qoff - 2] + 0xe8c7b756;
		const uint32 tt17 = GG(Q[Qoff + 16], Q[Qoff + 15], Q[Qoff + 14]) + Q[Qoff + 13] + 0xf61e2562;
		const uint32 tt18 = Q[Qoff + 14] + 0xc040b340 + block[6];
		const uint32 tt19 = Q[Qoff + 15] + 0x265e5a51 + block[11];
		const uint32 tt20 = Q[Qoff + 16] + 0xe9b6c7aa + block[0];
		const uint32 tt5 = RR(Q[Qoff + 6] - Q[Qoff + 5], 12) - FF(Q[Qoff + 5], Q[Qoff + 4], Q[Qoff + 3]) - 0x4787c62a;

		// change q17 until conditions are met on q18, q19 and q20
		unsigned counter = 0;
		while (counter < (1 << 7))
		{
			const uint32 q16 = Q[Qoff + 16];
			uint32 q17 = ((xrng64() & 0x3ffd7ff7) | (q16 & 0xc0008008)) ^ 0x40000000;
			++counter;

			uint32 q18 = GG(q17, q16, Q[Qoff + 15]) + tt18;
			q18 = RL(q18, 9); q18 += q17;
			if (0x00020000 != ((q18 ^ q17) & 0xa0020000))
				continue;

			uint32 q19 = GG(q18, q17, q16) + tt19;
			q19 = RL(q19, 14); q19 += q18;
			if (0x80000000 != (q19 & 0x80020000))
				continue;

			uint32 q20 = GG(q19, q18, q17) + tt20;
			q20 = RL(q20, 20); q20 += q19;
			if (0x00040000 != ((q20 ^ q19) & 0x80040000))
				continue;

			block[1] = q17 - q16; block[1] = RR(block[1], 5); block[1] -= tt17;
			uint32 q2 = block[1] + tt1; q2 = RL(q2, 12); q2 += Q[Qoff + 1];
			block[5] = tt5 - q2;

			Q[Qoff + 2] = q2;
			Q[Qoff + 17] = q17;
			Q[Qoff + 18] = q18;
			Q[Qoff + 19] = q19;
			Q[Qoff + 20] = q20;
			MD5_REVERSE_STEP(2, 0x242070db, 17);

			counter = 0;
			break;
		}
		if (counter != 0)
			continue;

		const uint32 q4 = Q[Qoff + 4];
		const uint32 q9backup = Q[Qoff + 9];
		const uint32 tt21 = GG(Q[Qoff + 20], Q[Qoff + 19], Q[Qoff + 18]) + Q[Qoff + 17] + 0xd62f105d;

		// iterate over possible changes of q4 
		// while keeping all conditions on q1-q20 intact
		// this changes m3, m4, m5 and m7
		unsigned counter2 = 0;
		while (counter2 < (1 << 4))
		{
			Q[Qoff + 4] = q4 ^ q4mask[counter2];
			++counter2;
			MD5_REVERSE_STEP(5, 0x4787c62a, 12);
			uint32 q21 = tt21 + block[5];
			q21 = RL(q21, 5); q21 += Q[Qoff + 20];
			if (0 != ((q21 ^ Q[Qoff + 20]) & 0x80020000))
				continue;

			Q[Qoff + 21] = q21;
			MD5_REVERSE_STEP(3, 0xc1bdceee, 22);
			MD5_REVERSE_STEP(4, 0xf57c0faf, 7);
			MD5_REVERSE_STEP(7, 0xfd469501, 22);

			const uint32 tt22 = GG(Q[Qoff + 21], Q[Qoff + 20], Q[Qoff + 19]) + Q[Qoff + 18] + 0x02441453;
			const uint32 tt23 = Q[Qoff + 19] + 0xd8a1e681 + block[15];
			const uint32 tt24 = Q[Qoff + 20] + 0xe7d3fbc8 + block[4];

			const uint32 tt9 = Q[Qoff + 6] + 0x8b44f7af;
			const uint32 tt10 = Q[Qoff + 7] + 0xffff5bb1;
			const uint32 tt8 = FF(Q[Qoff + 8], Q[Qoff + 7], Q[Qoff + 6]) + Q[Qoff + 5] + 0x698098d8;
			const uint32 tt12 = RR(Q[Qoff + 13] - Q[Qoff + 12], 7) - 0x6b901122;
			const uint32 tt13 = RR(Q[Qoff + 14] - Q[Qoff + 13], 12) - FF(Q[Qoff + 13], Q[Qoff + 12], Q[Qoff + 11]) - 0xfd987193;

			// iterate over possible changes of q9 and q10
			// while keeping conditions on q1-q21 intact
			// this changes m8, m9, m10, m12 and m13 (and not m11!)
			// the possible changes of q9 that also do not change m10 are used below
			for (unsigned counter3 = 0; counter3 < (1 << 3);)
			{
				uint32 q10 = Q[Qoff + 10] ^ (q9q10mask[counter3] & 0x60);
				Q[Qoff + 9] = q9backup ^ (q9q10mask[counter3] & 0x2000);
				++counter3;
				uint32 m10 = RR(Q[Qoff + 11] - q10, 17);
				m10 -= FF(q10, Q[Qoff + 9], Q[Qoff + 8]) + tt10;

				uint32 aa = Q[Qoff + 21];
				uint32 dd = tt22 + m10; dd = RL(dd, 9) + aa;
				if (0x80000000 != (dd & 0x80000000)) continue;

				uint32 bb = Q[Qoff + 20];
				uint32 cc = tt23 + GG(dd, aa, bb);
				if (0 != (cc & 0x20000)) continue;
				cc = RL(cc, 14) + dd;
				if (0 != (cc & 0x80000000)) continue;

				bb = tt24 + GG(cc, dd, aa); bb = RL(bb, 20) + cc;
				if (0 == (bb & 0x80000000)) continue;

				block[10] = m10;
				block[13] = tt13 - q10;

				// iterate over possible changes of q9
				// while keeping intact conditions on q1-q24
				// this changes m8, m9 and m12 (but not m10!)
				for (unsigned counter4 = 0; counter4 < (1 << 16); ++counter4)
				{
					uint32 q9 = Q[Qoff + 9] ^ q9mask[counter4];
					block[12] = tt12 - FF(Q[Qoff + 12], Q[Qoff + 11], q10) - q9;
					uint32 m8 = q9 - Q[Qoff + 8];
					block[8] = RR(m8, 7) - tt8;
					uint32 m9 = q10 - q9;
					block[9] = RR(m9, 12) - FF(q9, Q[Qoff + 8], Q[Qoff + 7]) - tt9;

					uint32 a = aa, b = bb, c = cc, d = dd;
					MD5_STEP(GG, a, b, c, d, block[9], 0x21e1cde6, 5);
					MD5_STEP(GG, d, a, b, c, block[14], 0xc33707d6, 9);
					MD5_STEP(GG, c, d, a, b, block[3], 0xf4d50d87, 14);
					MD5_STEP(GG, b, c, d, a, block[8], 0x455a14ed, 20);
					MD5_STEP(GG, a, b, c, d, block[13], 0xa9e3e905, 5);
					MD5_STEP(GG, d, a, b, c, block[2], 0xfcefa3f8, 9);
					MD5_STEP(GG, c, d, a, b, block[7], 0x676f02d9, 14);
					MD5_STEP(GG, b, c, d, a, block[12], 0x8d2a4c8a, 20);
					MD5_STEP(HH, a, b, c, d, block[5], 0xfffa3942, 4);
					MD5_STEP(HH, d, a, b, c, block[8], 0x8771f681, 11);

					c += HH(d, a, b) + block[11] + 0x6d9d6122;
					if (0 != (c & (1 << 15)))
						continue;
					c = (c << 16 | c >> 16) + d;

					MD5_STEP(HH, b, c, d, a, block[14], 0xfde5380c, 23);
					MD5_STEP(HH, a, b, c, d, block[1], 0xa4beea44, 4);
					MD5_STEP(HH, d, a, b, c, block[4], 0x4bdecfa9, 11);
					MD5_STEP(HH, c, d, a, b, block[7], 0xf6bb4b60, 16);
					MD5_STEP(HH, b, c, d, a, block[10], 0xbebfbc70, 23);
					MD5_STEP(HH, a, b, c, d, block[13], 0x289b7ec6, 4);
					MD5_STEP(HH, d, a, b, c, block[0], 0xeaa127fa, 11);
					MD5_STEP(HH, c, d, a, b, block[3], 0xd4ef3085, 16);
					MD5_STEP(HH, b, c, d, a, block[6], 0x04881d05, 23);
					MD5_STEP(HH, a, b, c, d, block[9], 0xd9d4d039, 4);
					MD5_STEP(HH, d, a, b, c, block[12], 0xe6db99e5, 11);
					MD5_STEP(HH, c, d, a, b, block[15], 0x1fa27cf8, 16);
					MD5_STEP(HH, b, c, d, a, block[2], 0xc4ac5665, 23);
					if (0 != ((b ^ d) & 0x80000000))
						continue;

					MD5_STEP(II, a, b, c, d, block[0], 0xf4292244, 6);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, d, a, b, c, block[7], 0x432aff97, 10);
					if (0 == ((b ^ d) >> 31)) continue;
					MD5_STEP(II, c, d, a, b, block[14], 0xab9423a7, 15);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, b, c, d, a, block[5], 0xfc93a039, 21);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, a, b, c, d, block[12], 0x655b59c3, 6);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, d, a, b, c, block[3], 0x8f0ccc92, 10);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, c, d, a, b, block[10], 0xffeff47d, 15);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, b, c, d, a, block[1], 0x85845dd1, 21);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, a, b, c, d, block[8], 0x6fa87e4f, 6);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, d, a, b, c, block[15], 0xfe2ce6e0, 10);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, c, d, a, b, block[6], 0xa3014314, 15);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, b, c, d, a, block[13], 0x4e0811a1, 21);
					if (0 == ((b ^ d) >> 31)) continue;
					MD5_STEP(II, a, b, c, d, block[4], 0xf7537e82, 6);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, d, a, b, c, block[11], 0xbd3af235, 10);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, c, d, a, b, block[2], 0x2ad7d2bb, 15);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, b, c, d, a, block[9], 0xeb86d391, 21);

					uint32 IHV1 = b + IV[1];
					uint32 IHV2 = c + IV[2];
					uint32 IHV3 = d + IV[3];

					bool wang = true;
					if (0x02000000 != ((IHV2 ^ IHV1) & 0x86000000)) wang = false;
					if (0 != ((IHV1 ^ IHV3) & 0x82000000)) wang = false;
					if (0 != (IHV1 & 0x06000020)) wang = false;

					bool stevens = true;
					if (((IHV1 ^ IHV2) >> 31) != 0 || ((IHV1 ^ IHV3) >> 31) != 0) stevens = false;
					if ((IHV3 & (1 << 25)) != 0 || (IHV2 & (1 << 25)) != 0 || (IHV1 & (1 << 25)) != 0
						|| ((IHV2 ^ IHV1) & 1) != 0) stevens = false;

					if (!(wang || stevens)) continue;

					uint32 IV1[4], IV2[4];
					for (int t = 0; t < 4; ++t)
						IV2[t] = IV1[t] = IV[t];

					uint32 block2[16];
					for (int t = 0; t < 16; ++t)
						block2[t] = block[t];
					block2[4] += 1 << 31;
					block2[11] += 1 << 15;
					block2[14] += 1 << 31;

					md5_compress(IV1, block);
					md5_compress(IV2, block2);
					if ((IV2[0] == IV1[0] + (1 << 31))
						&& (IV2[1] == IV1[1] + (1 << 31) + (1 << 25))
						&& (IV2[2] == IV1[2] + (1 << 31) + (1 << 25))
						&& (IV2[3] == IV1[3] + (1 << 31) + (1 << 25)))
						return;

					if (IV2[0] != IV1[0] + (1 << 31))
						std::cout << "!" << std::flush;
				}
			}
		}
	}
}

void find_block1(uint32 block[], const uint32 IV[])
{
	if (((IV[1] ^ IV[2]) & (1 << 31)) == 0 && ((IV[1] ^ IV[3]) & (1 << 31)) == 0
		&& (IV[3] & (1 << 25)) == 0 && (IV[2] & (1 << 25)) == 0 && (IV[1] & (1 << 25)) == 0 && ((IV[2] ^ IV[1]) & 1) == 0
		)
	{
		uint32 IV2[4] = { IV[0] + (1 << 31), IV[1] + (1 << 31) + (1 << 25), IV[2] + (1 << 31) + (1 << 25), IV[3] + (1 << 31) + (1 << 25) };
		if ((IV[1] & (1 << 6)) != 0 && (IV[1] & 1) != 0) {
			find_block1_stevens_11(block, IV2);
		}
		else if ((IV[1] & (1 << 6)) != 0 && (IV[1] & 1) == 0) {
			find_block1_stevens_10(block, IV2);
		}
		else if ((IV[1] & (1 << 6)) == 0 && (IV[1] & 1) != 0) {
			find_block1_stevens_01(block, IV2);
		}
		else {
			find_block1_stevens_00(block, IV2);
		}
		block[4] += 1 << 31;
		block[11] += 1 << 15;
		block[14] += 1 << 31;
	}
	else {
		find_block1_wang(block, IV);
	}
}

void find_block1_stevens_00(uint32 block[], const uint32 IV[])
{
	uint32 Q[68] = { IV[0], IV[3], IV[2], IV[1] };

	std::vector<uint32> q9q10mask(1 << 3);
	for (unsigned k = 0; k < q9q10mask.size(); ++k)
		q9q10mask[k] = ((k << 5) ^ (k << 12) ^ (k << 25)) & 0x08002020;

	std::vector<uint32> q9mask(1 << 9);
	for (unsigned k = 0; k < q9mask.size(); ++k)
		q9mask[k] = ((k << 1) ^ (k << 3) ^ (k << 6) ^ (k << 8) ^ (k << 11) ^ (k << 14) ^ (k << 18)) & 0x04310d12;

	while (true)
	{
		uint32 aa = Q[Qoff] & 0x80000000;

		Q[Qoff + 2] = (xrng64() & 0x49a0e73e) | 0x221f00c1 | aa;
		Q[Qoff + 3] = (xrng64() & 0x0000040c) | 0x3fce1a71 | (Q[Qoff + 2] & 0x8000e000);
		Q[Qoff + 4] = (xrng64() & 0x00000004) | (0xa5f281a2 ^ (Q[Qoff + 3] & 0x80000008));
		Q[Qoff + 5] = (xrng64() & 0x00000004) | 0x67fd823b;
		Q[Qoff + 6] = (xrng64() & 0x00001044) | 0x15e5829a;
		Q[Qoff + 7] = (xrng64() & 0x00200806) | 0x950430b0;
		Q[Qoff + 8] = (xrng64() & 0x60050110) | 0x1bd29ca2 | (Q[Qoff + 7] & 0x00000004);
		Q[Qoff + 9] = (xrng64() & 0x40044000) | 0xb8820004;
		Q[Qoff + 10] = 0xf288b209 | (Q[Qoff + 9] & 0x00044000);
		Q[Qoff + 11] = (xrng64() & 0x12888008) | 0x85712f57;
		Q[Qoff + 12] = (xrng64() & 0x1ed98d7f) | 0xc0023080 | (~Q[Qoff + 11] & 0x00200000);
		Q[Qoff + 13] = (xrng64() & 0x0efb1d77) | 0x1000c008;
		Q[Qoff + 14] = (xrng64() & 0x0fff5d77) | 0xa000a288;
		Q[Qoff + 15] = (xrng64() & 0x0efe7ff7) | 0xe0008000 | (~Q[Qoff + 14] & 0x00010000);
		Q[Qoff + 16] = (xrng64() & 0x0ffdffff) | 0xf0000000 | (~Q[Qoff + 15] & 0x00020000);

		MD5_REVERSE_STEP(5, 0x4787c62a, 12);
		MD5_REVERSE_STEP(6, 0xa8304613, 17);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);
		MD5_REVERSE_STEP(11, 0x895cd7be, 22);
		MD5_REVERSE_STEP(14, 0xa679438e, 17);
		MD5_REVERSE_STEP(15, 0x49b40821, 22);

		const uint32 tt17 = GG(Q[Qoff + 16], Q[Qoff + 15], Q[Qoff + 14]) + Q[Qoff + 13] + 0xf61e2562;
		const uint32 tt18 = Q[Qoff + 14] + 0xc040b340 + block[6];
		const uint32 tt19 = Q[Qoff + 15] + 0x265e5a51 + block[11];

		const uint32 tt0 = FF(Q[Qoff + 0], Q[Qoff - 1], Q[Qoff - 2]) + Q[Qoff - 3] + 0xd76aa478;
		const uint32 tt1 = Q[Qoff - 2] + 0xe8c7b756;
		const uint32 q1a = 0x02020801 | (Q[Qoff + 0] & 0x80000000);

		unsigned counter = 0;
		while (counter < (1 << 12))
		{
			++counter;

			uint32 q1 = q1a | (xrng64() & 0x7dfdf7be);
			uint32 m1 = Q[Qoff + 2] - q1;
			m1 = RR(m1, 12) - FF(q1, Q[Qoff + 0], Q[Qoff - 1]) - tt1;

			const uint32 q16 = Q[Qoff + 16];
			uint32 q17 = tt17 + m1;
			q17 = RL(q17, 5) + q16;
			if (0x80000000 != ((q17 ^ q16) & 0x80008008)) continue;
			if (0 != (q17 & 0x00020000)) continue;

			uint32 q18 = GG(q17, q16, Q[Qoff + 15]) + tt18;
			q18 = RL(q18, 9); q18 += q17;
			if (0x80020000 != ((q18 ^ q17) & 0xa0020000)) continue;

			uint32 q19 = GG(q18, q17, q16) + tt19;
			q19 = RL(q19, 14); q19 += q18;
			if (0x80000000 != (q19 & 0x80020000)) continue;

			uint32 m0 = q1 - Q[Qoff + 0];
			m0 = RR(m0, 7) - tt0;

			uint32 q20 = GG(q19, q18, q17) + q16 + 0xe9b6c7aa + m0;
			q20 = RL(q20, 20); q20 += q19;
			if (0x00040000 != ((q20 ^ q19) & 0x80040000))	continue;

			Q[Qoff + 1] = q1;
			Q[Qoff + 17] = q17;
			Q[Qoff + 18] = q18;
			Q[Qoff + 19] = q19;
			Q[Qoff + 20] = q20;

			block[0] = m0;
			block[1] = m1;

			MD5_REVERSE_STEP(5, 0x4787c62a, 12);
			uint32 q21 = GG(Q[Qoff + 20], Q[Qoff + 19], Q[Qoff + 18]) + Q[Qoff + 17] + 0xd62f105d + block[5];
			q21 = RL(q21, 5); q21 += Q[Qoff + 20];
			if (0 != ((q21 ^ Q[Qoff + 20]) & 0x80020000)) continue;
			Q[Qoff + 21] = q21;

			counter = 0;
			break;
		}
		if (counter != 0)
			continue;

		const uint32 q9b = Q[Qoff + 9];
		const uint32 q10b = Q[Qoff + 10];

		MD5_REVERSE_STEP(2, 0x242070db, 17);
		MD5_REVERSE_STEP(3, 0xc1bdceee, 22);
		MD5_REVERSE_STEP(4, 0xf57c0faf, 7);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);

		const uint32 tt10 = Q[Qoff + 7] + 0xffff5bb1;
		const uint32 tt22 = GG(Q[Qoff + 21], Q[Qoff + 20], Q[Qoff + 19]) + Q[Qoff + 18] + 0x02441453;
		const uint32 tt23 = Q[Qoff + 19] + 0xd8a1e681 + block[15];
		const uint32 tt24 = Q[Qoff + 20] + 0xe7d3fbc8 + block[4];

		for (unsigned k10 = 0; k10 < (1 << 3); ++k10)
		{
			uint32 q10 = q10b | (q9q10mask[k10] & 0x08000020);
			uint32 m10 = RR(Q[Qoff + 11] - q10, 17);
			uint32 q9 = q9b | (q9q10mask[k10] & 0x00002000);

			m10 -= FF(q10, q9, Q[Qoff + 8]) + tt10;

			uint32 aa = Q[Qoff + 21];
			uint32 dd = tt22 + m10; dd = RL(dd, 9) + aa;
			if (0 == (dd & 0x80000000)) continue;

			uint32 bb = Q[Qoff + 20];
			uint32 cc = tt23 + GG(dd, aa, bb);
			if (0 != (cc & 0x20000)) continue;
			cc = RL(cc, 14) + dd;
			if (0 != (cc & 0x80000000)) continue;

			bb = tt24 + GG(cc, dd, aa); bb = RL(bb, 20) + cc;
			if (0 == (bb & 0x80000000)) continue;

			block[10] = m10;
			Q[Qoff + 9] = q9;
			Q[Qoff + 10] = q10;
			MD5_REVERSE_STEP(13, 0xfd987193, 12);

			for (unsigned k9 = 0; k9 < (1 << 9); ++k9)
			{
				uint32 a = aa, b = bb, c = cc, d = dd;
				Q[Qoff + 9] = q9 ^ q9mask[k9];
				MD5_REVERSE_STEP(8, 0x698098d8, 7);
				MD5_REVERSE_STEP(9, 0x8b44f7af, 12);
				MD5_REVERSE_STEP(12, 0x6b901122, 7);

				MD5_STEP(GG, a, b, c, d, block[9], 0x21e1cde6, 5);
				MD5_STEP(GG, d, a, b, c, block[14], 0xc33707d6, 9);
				MD5_STEP(GG, c, d, a, b, block[3], 0xf4d50d87, 14);
				MD5_STEP(GG, b, c, d, a, block[8], 0x455a14ed, 20);
				MD5_STEP(GG, a, b, c, d, block[13], 0xa9e3e905, 5);
				MD5_STEP(GG, d, a, b, c, block[2], 0xfcefa3f8, 9);
				MD5_STEP(GG, c, d, a, b, block[7], 0x676f02d9, 14);
				MD5_STEP(GG, b, c, d, a, block[12], 0x8d2a4c8a, 20);
				MD5_STEP(HH, a, b, c, d, block[5], 0xfffa3942, 4);
				MD5_STEP(HH, d, a, b, c, block[8], 0x8771f681, 11);

				c += HH(d, a, b) + block[11] + 0x6d9d6122;
				if (0 != (c & (1 << 15)))
					continue;
				c = (c << 16 | c >> 16) + d;

				MD5_STEP(HH, b, c, d, a, block[14], 0xfde5380c, 23);
				MD5_STEP(HH, a, b, c, d, block[1], 0xa4beea44, 4);
				MD5_STEP(HH, d, a, b, c, block[4], 0x4bdecfa9, 11);
				MD5_STEP(HH, c, d, a, b, block[7], 0xf6bb4b60, 16);
				MD5_STEP(HH, b, c, d, a, block[10], 0xbebfbc70, 23);
				MD5_STEP(HH, a, b, c, d, block[13], 0x289b7ec6, 4);
				MD5_STEP(HH, d, a, b, c, block[0], 0xeaa127fa, 11);
				MD5_STEP(HH, c, d, a, b, block[3], 0xd4ef3085, 16);
				MD5_STEP(HH, b, c, d, a, block[6], 0x04881d05, 23);
				MD5_STEP(HH, a, b, c, d, block[9], 0xd9d4d039, 4);
				MD5_STEP(HH, d, a, b, c, block[12], 0xe6db99e5, 11);
				MD5_STEP(HH, c, d, a, b, block[15], 0x1fa27cf8, 16);
				MD5_STEP(HH, b, c, d, a, block[2], 0xc4ac5665, 23);
				if (0 != ((b ^ d) & 0x80000000))
					continue;

				MD5_STEP(II, a, b, c, d, block[0], 0xf4292244, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[7], 0x432aff97, 10);
				if (0 == ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[14], 0xab9423a7, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[5], 0xfc93a039, 21);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[12], 0x655b59c3, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[3], 0x8f0ccc92, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[10], 0xffeff47d, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[1], 0x85845dd1, 21);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[8], 0x6fa87e4f, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[15], 0xfe2ce6e0, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[6], 0xa3014314, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[13], 0x4e0811a1, 21);
				if (0 == ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[4], 0xf7537e82, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[11], 0xbd3af235, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[2], 0x2ad7d2bb, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[9], 0xeb86d391, 21);

				uint32 block2[16];
				uint32 IV1[4], IV2[4];
				for (int t = 0; t < 4; ++t)
				{
					IV1[t] = IV[t];
					IV2[t] = IV[t] + (1 << 31);
				}
				IV2[1] -= (1 << 25);
				IV2[2] -= (1 << 25);
				IV2[3] -= (1 << 25);

				for (int t = 0; t < 16; ++t)
					block2[t] = block[t];
				block2[4] += 1 << 31;
				block2[11] += 1 << 15;
				block2[14] += 1 << 31;

				md5_compress(IV1, block);
				md5_compress(IV2, block2);
				if (IV2[0] == IV1[0] && IV2[1] == IV1[1] && IV2[2] == IV1[2] && IV2[3] == IV1[3])
					return;
				if (IV2[0] != IV1[0])
					std::cout << "!" << std::flush;
			}
		}
	}
}

void find_block1_stevens_01(uint32 block[], const uint32 IV[])
{
	uint32 Q[68] = { IV[0], IV[3], IV[2], IV[1] };

	std::vector<uint32> q9q10mask(1 << 5);
	for (unsigned k = 0; k < q9q10mask.size(); ++k)
		q9q10mask[k] = ((k << 4) ^ (k << 11) ^ (k << 24) ^ (k << 27)) & 0x88002030;

	std::vector<uint32> q9mask(1 << 9);
	for (unsigned k = 0; k < q9mask.size(); ++k)
		q9mask[k] = ((k << 1) ^ (k << 7) ^ (k << 9) ^ (k << 12) ^ (k << 15) ^ (k << 19) ^ (k << 22)) & 0x44310d02;

	while (true)
	{
		uint32 aa = Q[Qoff] & 0x80000000;

		Q[Qoff + 2] = (xrng64() & 0x4db0e03e) | 0x32460441 | aa;
		Q[Qoff + 3] = (xrng64() & 0x0c000008) | 0x123c3af1 | (Q[Qoff + 2] & 0x80800002);
		Q[Qoff + 4] = 0xe398f812 ^ (Q[Qoff + 3] & 0x88000000);
		Q[Qoff + 5] = (xrng64() & 0x82000000) | 0x4c66e99e;
		Q[Qoff + 6] = (xrng64() & 0x80000000) | 0x27180590;
		Q[Qoff + 7] = (xrng64() & 0x00010130) | 0x51ea9e47;
		Q[Qoff + 8] = (xrng64() & 0x40200800) | 0xb7c291e5;
		Q[Qoff + 9] = (xrng64() & 0x00044000) | 0x380002b4;
		Q[Qoff + 10] = 0xb282b208 | (Q[Qoff + 9] & 0x00044000);
		Q[Qoff + 11] = (xrng64() & 0x12808008) | 0xc5712f47;
		Q[Qoff + 12] = (xrng64() & 0x1ef18d7f) | 0x000a3080;
		Q[Qoff + 13] = (xrng64() & 0x1efb1d77) | 0x4004c008;
		Q[Qoff + 14] = (xrng64() & 0x1fff5d77) | 0x6000a288;
		Q[Qoff + 15] = (xrng64() & 0x1efe7ff7) | 0xa0008000 | (~Q[Qoff + 14] & 0x00010000);
		Q[Qoff + 16] = (xrng64() & 0x1ffdffff) | 0x20000000 | (~Q[Qoff + 15] & 0x00020000);

		MD5_REVERSE_STEP(5, 0x4787c62a, 12);
		MD5_REVERSE_STEP(6, 0xa8304613, 17);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);
		MD5_REVERSE_STEP(11, 0x895cd7be, 22);
		MD5_REVERSE_STEP(14, 0xa679438e, 17);
		MD5_REVERSE_STEP(15, 0x49b40821, 22);

		const uint32 tt17 = GG(Q[Qoff + 16], Q[Qoff + 15], Q[Qoff + 14]) + Q[Qoff + 13] + 0xf61e2562;
		const uint32 tt18 = Q[Qoff + 14] + 0xc040b340 + block[6];
		const uint32 tt19 = Q[Qoff + 15] + 0x265e5a51 + block[11];

		const uint32 tt0 = FF(Q[Qoff + 0], Q[Qoff - 1], Q[Qoff - 2]) + Q[Qoff - 3] + 0xd76aa478;
		const uint32 tt1 = Q[Qoff - 2] + 0xe8c7b756;

		const uint32 q1a = 0x02000021 ^ (Q[Qoff + 0] & 0x80000020);

		unsigned counter = 0;
		while (counter < (1 << 12))
		{
			++counter;

			uint32 q1 = q1a | (xrng64() & 0x7dfff39e);
			uint32 m1 = Q[Qoff + 2] - q1;
			m1 = RR(m1, 12) - FF(q1, Q[Qoff + 0], Q[Qoff - 1]) - tt1;

			const uint32 q16 = Q[Qoff + 16];
			uint32 q17 = tt17 + m1;
			q17 = RL(q17, 5) + q16;
			if (0x80000000 != ((q17 ^ q16) & 0x80008008)) continue;
			if (0 != (q17 & 0x00020000)) continue;

			uint32 q18 = GG(q17, q16, Q[Qoff + 15]) + tt18;
			q18 = RL(q18, 9); q18 += q17;
			if (0x80020000 != ((q18 ^ q17) & 0xa0020000)) continue;

			uint32 q19 = GG(q18, q17, q16) + tt19;
			q19 = RL(q19, 14); q19 += q18;
			if (0 != (q19 & 0x80020000)) continue;

			uint32 m0 = q1 - Q[Qoff + 0];
			m0 = RR(m0, 7) - tt0;

			uint32 q20 = GG(q19, q18, q17) + q16 + 0xe9b6c7aa + m0;
			q20 = RL(q20, 20); q20 += q19;
			if (0x00040000 != ((q20 ^ q19) & 0x80040000))	continue;

			Q[Qoff + 1] = q1;
			Q[Qoff + 17] = q17;
			Q[Qoff + 18] = q18;
			Q[Qoff + 19] = q19;
			Q[Qoff + 20] = q20;

			block[0] = m0;
			block[1] = m1;

			MD5_REVERSE_STEP(5, 0x4787c62a, 12);
			uint32 q21 = GG(Q[Qoff + 20], Q[Qoff + 19], Q[Qoff + 18]) + Q[Qoff + 17] + 0xd62f105d + block[5];
			q21 = RL(q21, 5); q21 += Q[Qoff + 20];
			if (0 != ((q21 ^ Q[Qoff + 20]) & 0x80020000)) continue;

			Q[Qoff + 21] = q21;

			counter = 0;
			break;
		}
		if (counter != 0)
			continue;

		const uint32 q9b = Q[Qoff + 9];
		const uint32 q10b = Q[Qoff + 10];

		MD5_REVERSE_STEP(2, 0x242070db, 17);
		MD5_REVERSE_STEP(3, 0xc1bdceee, 22);
		MD5_REVERSE_STEP(4, 0xf57c0faf, 7);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);

		const uint32 tt10 = Q[Qoff + 7] + 0xffff5bb1;
		const uint32 tt22 = GG(Q[Qoff + 21], Q[Qoff + 20], Q[Qoff + 19]) + Q[Qoff + 18] + 0x02441453;
		const uint32 tt23 = Q[Qoff + 19] + 0xd8a1e681 + block[15];
		const uint32 tt24 = Q[Qoff + 20] + 0xe7d3fbc8 + block[4];

		for (unsigned k10 = 0; k10 < (1 << 5); ++k10)
		{
			uint32 q10 = q10b | (q9q10mask[k10] & 0x08000030);
			uint32 m10 = RR(Q[Qoff + 11] - q10, 17);
			uint32 q9 = q9b | (q9q10mask[k10] & 0x80002000);

			m10 -= FF(q10, q9, Q[Qoff + 8]) + tt10;

			uint32 aa = Q[Qoff + 21];
			uint32 dd = tt22 + m10; dd = RL(dd, 9) + aa;
			if (0 != (dd & 0x80000000)) continue;

			uint32 bb = Q[Qoff + 20];
			uint32 cc = tt23 + GG(dd, aa, bb);
			if (0 != (cc & 0x20000)) continue;
			cc = RL(cc, 14) + dd;
			if (0 != (cc & 0x80000000)) continue;

			bb = tt24 + GG(cc, dd, aa); bb = RL(bb, 20) + cc;
			if (0 == (bb & 0x80000000)) continue;

			block[10] = m10;
			Q[Qoff + 9] = q9;
			Q[Qoff + 10] = q10;
			MD5_REVERSE_STEP(13, 0xfd987193, 12);

			for (unsigned k9 = 0; k9 < (1 << 9); ++k9)
			{
				uint32 a = aa, b = bb, c = cc, d = dd;
				Q[Qoff + 9] = q9 ^ q9mask[k9];
				MD5_REVERSE_STEP(8, 0x698098d8, 7);
				MD5_REVERSE_STEP(9, 0x8b44f7af, 12);
				MD5_REVERSE_STEP(12, 0x6b901122, 7);

				MD5_STEP(GG, a, b, c, d, block[9], 0x21e1cde6, 5);
				MD5_STEP(GG, d, a, b, c, block[14], 0xc33707d6, 9);
				MD5_STEP(GG, c, d, a, b, block[3], 0xf4d50d87, 14);
				MD5_STEP(GG, b, c, d, a, block[8], 0x455a14ed, 20);
				MD5_STEP(GG, a, b, c, d, block[13], 0xa9e3e905, 5);
				MD5_STEP(GG, d, a, b, c, block[2], 0xfcefa3f8, 9);
				MD5_STEP(GG, c, d, a, b, block[7], 0x676f02d9, 14);
				MD5_STEP(GG, b, c, d, a, block[12], 0x8d2a4c8a, 20);
				MD5_STEP(HH, a, b, c, d, block[5], 0xfffa3942, 4);
				MD5_STEP(HH, d, a, b, c, block[8], 0x8771f681, 11);

				c += HH(d, a, b) + block[11] + 0x6d9d6122;
				if (0 != (c & (1 << 15)))
					continue;
				c = (c << 16 | c >> 16) + d;

				MD5_STEP(HH, b, c, d, a, block[14], 0xfde5380c, 23);
				MD5_STEP(HH, a, b, c, d, block[1], 0xa4beea44, 4);
				MD5_STEP(HH, d, a, b, c, block[4], 0x4bdecfa9, 11);
				MD5_STEP(HH, c, d, a, b, block[7], 0xf6bb4b60, 16);
				MD5_STEP(HH, b, c, d, a, block[10], 0xbebfbc70, 23);
				MD5_STEP(HH, a, b, c, d, block[13], 0x289b7ec6, 4);
				MD5_STEP(HH, d, a, b, c, block[0], 0xeaa127fa, 11);
				MD5_STEP(HH, c, d, a, b, block[3], 0xd4ef3085, 16);
				MD5_STEP(HH, b, c, d, a, block[6], 0x04881d05, 23);
				MD5_STEP(HH, a, b, c, d, block[9], 0xd9d4d039, 4);
				MD5_STEP(HH, d, a, b, c, block[12], 0xe6db99e5, 11);
				MD5_STEP(HH, c, d, a, b, block[15], 0x1fa27cf8, 16);
				MD5_STEP(HH, b, c, d, a, block[2], 0xc4ac5665, 23);
				if (0 != ((b ^ d) & 0x80000000))
					continue;

				MD5_STEP(II, a, b, c, d, block[0], 0xf4292244, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[7], 0x432aff97, 10);
				if (0 == ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[14], 0xab9423a7, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[5], 0xfc93a039, 21);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[12], 0x655b59c3, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[3], 0x8f0ccc92, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[10], 0xffeff47d, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[1], 0x85845dd1, 21);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[8], 0x6fa87e4f, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[15], 0xfe2ce6e0, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[6], 0xa3014314, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[13], 0x4e0811a1, 21);
				if (0 == ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[4], 0xf7537e82, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[11], 0xbd3af235, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[2], 0x2ad7d2bb, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[9], 0xeb86d391, 21);

				uint32 block2[16];
				uint32 IV1[4], IV2[4];
				for (int t = 0; t < 4; ++t)
				{
					IV1[t] = IV[t];
					IV2[t] = IV[t] + (1 << 31);
				}
				IV2[1] -= (1 << 25);
				IV2[2] -= (1 << 25);
				IV2[3] -= (1 << 25);

				for (int t = 0; t < 16; ++t)
					block2[t] = block[t];
				block2[4] += 1 << 31;
				block2[11] += 1 << 15;
				block2[14] += 1 << 31;

				md5_compress(IV1, block);
				md5_compress(IV2, block2);
				if (IV2[0] == IV1[0] && IV2[1] == IV1[1] && IV2[2] == IV1[2] && IV2[3] == IV1[3])
					return;
				if (IV2[0] != IV1[0])
					std::cout << "!" << std::flush;
			}
		}
	}
}

void find_block1_stevens_10(uint32 block[], const uint32 IV[])
{
	uint32 Q[68] = { IV[0], IV[3], IV[2], IV[1] };

	std::vector<uint32> q9q10mask(1 << 4);
	for (unsigned k = 0; k < q9q10mask.size(); ++k)
		q9q10mask[k] = ((k << 2) ^ (k << 8) ^ (k << 11) ^ (k << 25)) & 0x08004204;

	std::vector<uint32> q9mask(1 << 10);
	for (unsigned k = 0; k < q9mask.size(); ++k)
		q9mask[k] = ((k << 1) ^ (k << 2) ^ (k << 3) ^ (k << 7) ^ (k << 12) ^ (k << 15) ^ (k << 18) ^ (k << 20)) & 0x2471042a;

	while (true)
	{
		uint32 aa = Q[Qoff] & 0x80000000;

		Q[Qoff + 2] = (xrng64() & 0x79b0c6ba) | 0x024c3841 | aa;
		Q[Qoff + 3] = (xrng64() & 0x19300210) | 0x2603096d | (Q[Qoff + 2] & 0x80000082);
		Q[Qoff + 4] = (xrng64() & 0x10300000) | 0xe4cae30c | (Q[Qoff + 3] & 0x01000030);
		Q[Qoff + 5] = (xrng64() & 0x10000000) | 0x63494061 | (Q[Qoff + 4] & 0x00300000);
		Q[Qoff + 6] = 0x7deaff68;
		Q[Qoff + 7] = (xrng64() & 0x20444000) | 0x09091ee0;
		Q[Qoff + 8] = (xrng64() & 0x09040000) | 0xb2529f6d;
		Q[Qoff + 9] = (xrng64() & 0x00040000) | 0x10885184;
		Q[Qoff + 10] = (xrng64() & 0x00000080) | 0x428afb11 | (Q[Qoff + 9] & 0x00040000);
		Q[Qoff + 11] = (xrng64() & 0x128a8110) | 0x6571266b | (Q[Qoff + 10] & 0x0000080);
		Q[Qoff + 12] = (xrng64() & 0x3ef38d7f) | 0x00003080 | (~Q[Qoff + 11] & 0x00080000);
		Q[Qoff + 13] = (xrng64() & 0x3efb1d77) | 0x0004c008;
		Q[Qoff + 14] = (xrng64() & 0x5fff5d77) | 0x8000a288;
		Q[Qoff + 15] = (xrng64() & 0x1efe7ff7) | 0xe0008000 | (~Q[Qoff + 14] & 0x00010000);
		Q[Qoff + 16] = (xrng64() & 0x5ffdffff) | 0x20000000 | (~Q[Qoff + 15] & 0x00020000);

		MD5_REVERSE_STEP(5, 0x4787c62a, 12);
		MD5_REVERSE_STEP(6, 0xa8304613, 17);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);
		MD5_REVERSE_STEP(11, 0x895cd7be, 22);
		MD5_REVERSE_STEP(14, 0xa679438e, 17);
		MD5_REVERSE_STEP(15, 0x49b40821, 22);

		const uint32 tt17 = GG(Q[Qoff + 16], Q[Qoff + 15], Q[Qoff + 14]) + Q[Qoff + 13] + 0xf61e2562;
		const uint32 tt18 = Q[Qoff + 14] + 0xc040b340 + block[6];
		const uint32 tt19 = Q[Qoff + 15] + 0x265e5a51 + block[11];

		const uint32 tt0 = FF(Q[Qoff + 0], Q[Qoff - 1], Q[Qoff - 2]) + Q[Qoff - 3] + 0xd76aa478;
		const uint32 tt1 = Q[Qoff - 2] + 0xe8c7b756;

		const uint32 q1a = 0x02000941 ^ (Q[Qoff + 0] & 0x80000000);

		unsigned counter = 0;
		while (counter < (1 << 12))
		{
			++counter;

			uint32 q1 = q1a | (xrng64() & 0x7dfdf6be);
			uint32 m1 = Q[Qoff + 2] - q1;
			m1 = RR(m1, 12) - FF(q1, Q[Qoff + 0], Q[Qoff - 1]) - tt1;

			const uint32 q16 = Q[Qoff + 16];
			uint32 q17 = tt17 + m1;
			q17 = RL(q17, 5) + q16;
			if (0x80000000 != ((q17 ^ q16) & 0x80008008)) continue;
			if (0 != (q17 & 0x00020000)) continue;

			uint32 q18 = GG(q17, q16, Q[Qoff + 15]) + tt18;
			q18 = RL(q18, 9); q18 += q17;
			if (0x80020000 != ((q18 ^ q17) & 0xa0020000)) continue;

			uint32 q19 = GG(q18, q17, q16) + tt19;
			q19 = RL(q19, 14); q19 += q18;
			if (0 != (q19 & 0x80020000)) continue;

			uint32 m0 = q1 - Q[Qoff + 0];
			m0 = RR(m0, 7) - tt0;

			uint32 q20 = GG(q19, q18, q17) + q16 + 0xe9b6c7aa + m0;
			q20 = RL(q20, 20); q20 += q19;
			if (0x00040000 != ((q20 ^ q19) & 0x80040000))	continue;

			Q[Qoff + 1] = q1;
			Q[Qoff + 17] = q17;
			Q[Qoff + 18] = q18;
			Q[Qoff + 19] = q19;
			Q[Qoff + 20] = q20;

			block[0] = m0;
			block[1] = m1;

			MD5_REVERSE_STEP(5, 0x4787c62a, 12);
			uint32 q21 = GG(Q[Qoff + 20], Q[Qoff + 19], Q[Qoff + 18]) + Q[Qoff + 17] + 0xd62f105d + block[5];
			q21 = RL(q21, 5); q21 += Q[Qoff + 20];
			if (0 != ((q21 ^ Q[Qoff + 20]) & 0x80020000)) continue;
			Q[Qoff + 21] = q21;

			counter = 0;
			break;
		}
		if (counter != 0)
			continue;

		const uint32 q9b = Q[Qoff + 9];
		const uint32 q10b = Q[Qoff + 10];

		MD5_REVERSE_STEP(2, 0x242070db, 17);
		MD5_REVERSE_STEP(3, 0xc1bdceee, 22);
		MD5_REVERSE_STEP(4, 0xf57c0faf, 7);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);

		const uint32 tt10 = Q[Qoff + 7] + 0xffff5bb1;
		const uint32 tt22 = GG(Q[Qoff + 21], Q[Qoff + 20], Q[Qoff + 19]) + Q[Qoff + 18] + 0x02441453;
		const uint32 tt23 = Q[Qoff + 19] + 0xd8a1e681 + block[15];
		const uint32 tt24 = Q[Qoff + 20] + 0xe7d3fbc8 + block[4];

		for (unsigned k10 = 0; k10 < (1 << 4); ++k10)
		{
			uint32 q10 = q10b | (q9q10mask[k10] & 0x08000004);
			uint32 m10 = RR(Q[Qoff + 11] - q10, 17);
			uint32 q9 = q9b | (q9q10mask[k10] & 0x00004200);

			m10 -= FF(q10, q9, Q[Qoff + 8]) + tt10;

			uint32 aa = Q[Qoff + 21];
			uint32 dd = tt22 + m10; dd = RL(dd, 9) + aa;
			if (0 != (dd & 0x80000000)) continue;

			uint32 bb = Q[Qoff + 20];
			uint32 cc = tt23 + GG(dd, aa, bb);
			if (0 != (cc & 0x20000)) continue;
			cc = RL(cc, 14) + dd;
			if (0 != (cc & 0x80000000)) continue;

			bb = tt24 + GG(cc, dd, aa); bb = RL(bb, 20) + cc;
			if (0 == (bb & 0x80000000)) continue;

			block[10] = m10;
			Q[Qoff + 9] = q9;
			Q[Qoff + 10] = q10;
			MD5_REVERSE_STEP(13, 0xfd987193, 12);

			for (unsigned k9 = 0; k9 < (1 << 10); ++k9)
			{
				uint32 a = aa, b = bb, c = cc, d = dd;
				Q[Qoff + 9] = q9 ^ q9mask[k9];
				MD5_REVERSE_STEP(8, 0x698098d8, 7);
				MD5_REVERSE_STEP(9, 0x8b44f7af, 12);
				MD5_REVERSE_STEP(12, 0x6b901122, 7);

				MD5_STEP(GG, a, b, c, d, block[9], 0x21e1cde6, 5);
				MD5_STEP(GG, d, a, b, c, block[14], 0xc33707d6, 9);
				MD5_STEP(GG, c, d, a, b, block[3], 0xf4d50d87, 14);
				MD5_STEP(GG, b, c, d, a, block[8], 0x455a14ed, 20);
				MD5_STEP(GG, a, b, c, d, block[13], 0xa9e3e905, 5);
				MD5_STEP(GG, d, a, b, c, block[2], 0xfcefa3f8, 9);
				MD5_STEP(GG, c, d, a, b, block[7], 0x676f02d9, 14);
				MD5_STEP(GG, b, c, d, a, block[12], 0x8d2a4c8a, 20);
				MD5_STEP(HH, a, b, c, d, block[5], 0xfffa3942, 4);
				MD5_STEP(HH, d, a, b, c, block[8], 0x8771f681, 11);

				c += HH(d, a, b) + block[11] + 0x6d9d6122;
				if (0 != (c & (1 << 15)))
					continue;
				c = (c << 16 | c >> 16) + d;

				MD5_STEP(HH, b, c, d, a, block[14], 0xfde5380c, 23);
				MD5_STEP(HH, a, b, c, d, block[1], 0xa4beea44, 4);
				MD5_STEP(HH, d, a, b, c, block[4], 0x4bdecfa9, 11);
				MD5_STEP(HH, c, d, a, b, block[7], 0xf6bb4b60, 16);
				MD5_STEP(HH, b, c, d, a, block[10], 0xbebfbc70, 23);
				MD5_STEP(HH, a, b, c, d, block[13], 0x289b7ec6, 4);
				MD5_STEP(HH, d, a, b, c, block[0], 0xeaa127fa, 11);
				MD5_STEP(HH, c, d, a, b, block[3], 0xd4ef3085, 16);
				MD5_STEP(HH, b, c, d, a, block[6], 0x04881d05, 23);
				MD5_STEP(HH, a, b, c, d, block[9], 0xd9d4d039, 4);
				MD5_STEP(HH, d, a, b, c, block[12], 0xe6db99e5, 11);
				MD5_STEP(HH, c, d, a, b, block[15], 0x1fa27cf8, 16);
				MD5_STEP(HH, b, c, d, a, block[2], 0xc4ac5665, 23);
				if (0 != ((b ^ d) & 0x80000000))
					continue;

				MD5_STEP(II, a, b, c, d, block[0], 0xf4292244, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[7], 0x432aff97, 10);
				if (0 == ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[14], 0xab9423a7, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[5], 0xfc93a039, 21);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[12], 0x655b59c3, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[3], 0x8f0ccc92, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[10], 0xffeff47d, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[1], 0x85845dd1, 21);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[8], 0x6fa87e4f, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[15], 0xfe2ce6e0, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[6], 0xa3014314, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[13], 0x4e0811a1, 21);
				if (0 == ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[4], 0xf7537e82, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[11], 0xbd3af235, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[2], 0x2ad7d2bb, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[9], 0xeb86d391, 21);

				uint32 block2[16];
				uint32 IV1[4], IV2[4];
				for (int t = 0; t < 4; ++t)
				{
					IV1[t] = IV[t];
					IV2[t] = IV[t] + (1 << 31);
				}
				IV2[1] -= (1 << 25);
				IV2[2] -= (1 << 25);
				IV2[3] -= (1 << 25);

				for (int t = 0; t < 16; ++t)
					block2[t] = block[t];
				block2[4] += 1 << 31;
				block2[11] += 1 << 15;
				block2[14] += 1 << 31;

				md5_compress(IV1, block);
				md5_compress(IV2, block2);
				if (IV2[0] == IV1[0] && IV2[1] == IV1[1] && IV2[2] == IV1[2] && IV2[3] == IV1[3])
					return;
				if (IV2[0] != IV1[0])
					std::cout << "!" << std::flush;
			}
		}
	}
}

void find_block1_stevens_11(uint32 block[], const uint32 IV[])
{
	uint32 Q[68] = { IV[0], IV[3], IV[2], IV[1] };

	std::vector<uint32> q9q10mask(1 << 5);
	for (unsigned k = 0; k < q9q10mask.size(); ++k)
		q9q10mask[k] = ((k << 5) ^ (k << 6) ^ (k << 7) ^ (k << 24) ^ (k << 27)) & 0x880002a0;

	std::vector<uint32> q9mask(1 << 9);
	for (unsigned k = 0; k < q9mask.size(); ++k)
		q9mask[k] = ((k << 1) ^ (k << 3) ^ (k << 8) ^ (k << 12) ^ (k << 15) ^ (k << 18)) & 0x04710c12;

	while (true)
	{
		uint32 aa = Q[Qoff] & 0x80000000;

		Q[Qoff + 2] = (xrng64() & 0x75bef63e) | 0x0a410041 | aa;
		Q[Qoff + 3] = (xrng64() & 0x10345614) | 0x0202a9e1 | (Q[Qoff + 2] & 0x84000002);
		Q[Qoff + 4] = (xrng64() & 0x00145400) | 0xe84ba909 | (Q[Qoff + 3] & 0x00000014);
		Q[Qoff + 5] = (xrng64() & 0x80000000) | 0x75e90b1d | (Q[Qoff + 4] & 0x00145400);
		Q[Qoff + 6] = 0x7c23ff5a | (Q[Qoff + 5] & 0x80000000);
		Q[Qoff + 7] = (xrng64() & 0x40000880) | 0x114bf41a;
		Q[Qoff + 8] = (xrng64() & 0x00002090) | 0xb352dd01;
		Q[Qoff + 9] = (xrng64() & 0x00044000) | 0x7a803124;
		Q[Qoff + 10] = (xrng64() & 0x00002000) | 0xf28a92c9 | (Q[Qoff + 9] & 0x00044000);
		Q[Qoff + 11] = (xrng64() & 0x128a8108) | 0xc5710ed7 | (Q[Qoff + 10] & 0x00002000);
		Q[Qoff + 12] = (xrng64() & 0x9edb8d7f) | 0x20003080 | (~Q[Qoff + 11] & 0x00200000);
		Q[Qoff + 13] = (xrng64() & 0x3efb1d77) | 0x4004c008 | (Q[Qoff + 12] & 0x80000000);
		Q[Qoff + 14] = (xrng64() & 0x1fff5d77) | 0x0000a288;
		Q[Qoff + 15] = (xrng64() & 0x1efe7ff7) | 0x20008000 | (~Q[Qoff + 14] & 0x00010000);
		Q[Qoff + 16] = (xrng64() & 0x1ffdffff) | 0x20000000 | (~Q[Qoff + 15] & 0x40020000);

		MD5_REVERSE_STEP(5, 0x4787c62a, 12);
		MD5_REVERSE_STEP(6, 0xa8304613, 17);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);
		MD5_REVERSE_STEP(11, 0x895cd7be, 22);
		MD5_REVERSE_STEP(14, 0xa679438e, 17);
		MD5_REVERSE_STEP(15, 0x49b40821, 22);

		const uint32 tt17 = GG(Q[Qoff + 16], Q[Qoff + 15], Q[Qoff + 14]) + Q[Qoff + 13] + 0xf61e2562;
		const uint32 tt18 = Q[Qoff + 14] + 0xc040b340 + block[6];
		const uint32 tt19 = Q[Qoff + 15] + 0x265e5a51 + block[11];

		const uint32 tt0 = FF(Q[Qoff + 0], Q[Qoff - 1], Q[Qoff - 2]) + Q[Qoff - 3] + 0xd76aa478;
		const uint32 tt1 = Q[Qoff - 2] + 0xe8c7b756;

		const uint32 q1a = 0x02000861 ^ (Q[Qoff + 0] & 0x80000020);

		unsigned counter = 0;
		while (counter < (1 << 12))
		{
			++counter;

			uint32 q1 = q1a | (xrng64() & 0x7dfff79e);
			uint32 m1 = Q[Qoff + 2] - q1;
			m1 = RR(m1, 12) - FF(q1, Q[Qoff + 0], Q[Qoff - 1]) - tt1;

			const uint32 q16 = Q[Qoff + 16];
			uint32 q17 = tt17 + m1;
			q17 = RL(q17, 5) + q16;
			if (0x40000000 != ((q17 ^ q16) & 0xc0008008)) continue;
			if (0 != (q17 & 0x00020000)) continue;

			uint32 q18 = GG(q17, q16, Q[Qoff + 15]) + tt18;
			q18 = RL(q18, 9); q18 += q17;
			if (0x80020000 != ((q18 ^ q17) & 0xa0020000)) continue;

			uint32 q19 = GG(q18, q17, q16) + tt19;
			q19 = RL(q19, 14); q19 += q18;
			if (0x80000000 != (q19 & 0x80020000)) continue;

			uint32 m0 = q1 - Q[Qoff + 0];
			m0 = RR(m0, 7) - tt0;

			uint32 q20 = GG(q19, q18, q17) + q16 + 0xe9b6c7aa + m0;
			q20 = RL(q20, 20); q20 += q19;
			if (0x00040000 != ((q20 ^ q19) & 0x80040000))	continue;

			Q[Qoff + 1] = q1;
			Q[Qoff + 17] = q17;
			Q[Qoff + 18] = q18;
			Q[Qoff + 19] = q19;
			Q[Qoff + 20] = q20;

			block[0] = m0;
			block[1] = m1;

			MD5_REVERSE_STEP(5, 0x4787c62a, 12);
			uint32 q21 = GG(Q[Qoff + 20], Q[Qoff + 19], Q[Qoff + 18]) + Q[Qoff + 17] + 0xd62f105d + block[5];
			q21 = RL(q21, 5); q21 += Q[Qoff + 20];
			if (0 != ((q21 ^ Q[Qoff + 20]) & 0x80020000)) continue;

			Q[Qoff + 21] = q21;

			counter = 0;
			break;
		}
		if (counter != 0)
			continue;

		const uint32 q9b = Q[Qoff + 9];
		const uint32 q10b = Q[Qoff + 10];

		MD5_REVERSE_STEP(2, 0x242070db, 17);
		MD5_REVERSE_STEP(3, 0xc1bdceee, 22);
		MD5_REVERSE_STEP(4, 0xf57c0faf, 7);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);

		const uint32 tt10 = Q[Qoff + 7] + 0xffff5bb1;
		const uint32 tt22 = GG(Q[Qoff + 21], Q[Qoff + 20], Q[Qoff + 19]) + Q[Qoff + 18] + 0x02441453;
		const uint32 tt23 = Q[Qoff + 19] + 0xd8a1e681 + block[15];
		const uint32 tt24 = Q[Qoff + 20] + 0xe7d3fbc8 + block[4];

		for (unsigned k10 = 0; k10 < (1 << 5); ++k10)
		{
			uint32 q10 = q10b | (q9q10mask[k10] & 0x08000040);
			uint32 m10 = RR(Q[Qoff + 11] - q10, 17);
			uint32 q9 = q9b | (q9q10mask[k10] & 0x80000280);

			m10 -= FF(q10, q9, Q[Qoff + 8]) + tt10;

			uint32 aa = Q[Qoff + 21];
			uint32 dd = tt22 + m10; dd = RL(dd, 9) + aa;
			if (0 == (dd & 0x80000000)) continue;

			uint32 bb = Q[Qoff + 20];
			uint32 cc = tt23 + GG(dd, aa, bb);
			if (0 != (cc & 0x20000)) continue;
			cc = RL(cc, 14) + dd;
			if (0 != (cc & 0x80000000)) continue;

			bb = tt24 + GG(cc, dd, aa); bb = RL(bb, 20) + cc;
			if (0 == (bb & 0x80000000)) continue;

			block[10] = m10;
			Q[Qoff + 9] = q9;
			Q[Qoff + 10] = q10;
			MD5_REVERSE_STEP(13, 0xfd987193, 12);

			for (unsigned k9 = 0; k9 < (1 << 9); ++k9)
			{
				uint32 a = aa, b = bb, c = cc, d = dd;
				Q[Qoff + 9] = q9 ^ q9mask[k9];
				MD5_REVERSE_STEP(8, 0x698098d8, 7);
				MD5_REVERSE_STEP(9, 0x8b44f7af, 12);
				MD5_REVERSE_STEP(12, 0x6b901122, 7);

				MD5_STEP(GG, a, b, c, d, block[9], 0x21e1cde6, 5);
				MD5_STEP(GG, d, a, b, c, block[14], 0xc33707d6, 9);
				MD5_STEP(GG, c, d, a, b, block[3], 0xf4d50d87, 14);
				MD5_STEP(GG, b, c, d, a, block[8], 0x455a14ed, 20);
				MD5_STEP(GG, a, b, c, d, block[13], 0xa9e3e905, 5);
				MD5_STEP(GG, d, a, b, c, block[2], 0xfcefa3f8, 9);
				MD5_STEP(GG, c, d, a, b, block[7], 0x676f02d9, 14);
				MD5_STEP(GG, b, c, d, a, block[12], 0x8d2a4c8a, 20);
				MD5_STEP(HH, a, b, c, d, block[5], 0xfffa3942, 4);
				MD5_STEP(HH, d, a, b, c, block[8], 0x8771f681, 11);

				c += HH(d, a, b) + block[11] + 0x6d9d6122;
				if (0 != (c & (1 << 15)))
					continue;
				c = (c << 16 | c >> 16) + d;

				MD5_STEP(HH, b, c, d, a, block[14], 0xfde5380c, 23);
				MD5_STEP(HH, a, b, c, d, block[1], 0xa4beea44, 4);
				MD5_STEP(HH, d, a, b, c, block[4], 0x4bdecfa9, 11);
				MD5_STEP(HH, c, d, a, b, block[7], 0xf6bb4b60, 16);
				MD5_STEP(HH, b, c, d, a, block[10], 0xbebfbc70, 23);
				MD5_STEP(HH, a, b, c, d, block[13], 0x289b7ec6, 4);
				MD5_STEP(HH, d, a, b, c, block[0], 0xeaa127fa, 11);
				MD5_STEP(HH, c, d, a, b, block[3], 0xd4ef3085, 16);
				MD5_STEP(HH, b, c, d, a, block[6], 0x04881d05, 23);
				MD5_STEP(HH, a, b, c, d, block[9], 0xd9d4d039, 4);
				MD5_STEP(HH, d, a, b, c, block[12], 0xe6db99e5, 11);
				MD5_STEP(HH, c, d, a, b, block[15], 0x1fa27cf8, 16);
				MD5_STEP(HH, b, c, d, a, block[2], 0xc4ac5665, 23);
				if (0 != ((b ^ d) & 0x80000000))
					continue;

				MD5_STEP(II, a, b, c, d, block[0], 0xf4292244, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[7], 0x432aff97, 10);
				if (0 == ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[14], 0xab9423a7, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[5], 0xfc93a039, 21);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[12], 0x655b59c3, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[3], 0x8f0ccc92, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[10], 0xffeff47d, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[1], 0x85845dd1, 21);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[8], 0x6fa87e4f, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[15], 0xfe2ce6e0, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[6], 0xa3014314, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[13], 0x4e0811a1, 21);
				if (0 == ((b ^ d) >> 31)) continue;
				MD5_STEP(II, a, b, c, d, block[4], 0xf7537e82, 6);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, d, a, b, c, block[11], 0xbd3af235, 10);
				if (0 != ((b ^ d) >> 31)) continue;
				MD5_STEP(II, c, d, a, b, block[2], 0x2ad7d2bb, 15);
				if (0 != ((a ^ c) >> 31)) continue;
				MD5_STEP(II, b, c, d, a, block[9], 0xeb86d391, 21);

				uint32 block2[16];
				uint32 IV1[4], IV2[4];
				for (int t = 0; t < 4; ++t)
				{
					IV1[t] = IV[t];
					IV2[t] = IV[t] + (1 << 31);
				}
				IV2[1] -= (1 << 25);
				IV2[2] -= (1 << 25);
				IV2[3] -= (1 << 25);

				for (int t = 0; t < 16; ++t)
					block2[t] = block[t];
				block2[4] += 1 << 31;
				block2[11] += 1 << 15;
				block2[14] += 1 << 31;

				md5_compress(IV1, block);
				md5_compress(IV2, block2);
				if (IV2[0] == IV1[0] && IV2[1] == IV1[1] && IV2[2] == IV1[2] && IV2[3] == IV1[3])
					return;
				if (IV2[0] != IV1[0])
					std::cout << "!" << std::flush;
			}
		}
	}
}

void find_block1_wang(uint32 block[], const uint32 IV[])
{
	uint32 Q[68] = { IV[0], IV[3], IV[2], IV[1] };

	std::vector<uint32> q4mask(1 << 6);
	for (unsigned k = 0; k < q4mask.size(); ++k)
		q4mask[k] = ((k << 13) ^ (k << 19)) & 0x01c0e000;

	std::vector<uint32> q9mask(1 << 5), q10mask(1 << 5);
	for (unsigned k = 0; k < q9mask.size(); ++k)
	{
		uint32 msk = (k << 5) ^ (k << 13) ^ (k << 17) ^ (k << 24);
		q9mask[k] = msk & 0x00084000;
		q10mask[k] = msk & 0x18000020;
	}

	std::vector<uint32> q9mask2(1 << 10);
	for (unsigned k = 0; k < q9mask2.size(); ++k)
		q9mask2[k] = ((k << 1) ^ (k << 7) ^ (k << 14) ^ (k << 15) ^ (k << 22)) & 0x6074041c;


	while (true)
	{
		uint32 aa = Q[Qoff] & 0x80000000;
		uint32 bb = 0x80000000 ^ aa;

		Q[Qoff + 2] = (xrng64() & 0x71de7799) | 0x0c008840 | bb;
		Q[Qoff + 3] = (xrng64() & 0x01c06601) | 0x3e1f0966 | (Q[Qoff + 2] & 0x80000018);
		Q[Qoff + 4] = 0x3a040010 | (Q[Qoff + 3] & 0x80000601);
		Q[Qoff + 5] = (xrng64() & 0x03c0e000) | 0x482f0e50 | aa;
		Q[Qoff + 6] = (xrng64() & 0x600c0000) | 0x05e2ec56 | aa;
		Q[Qoff + 7] = (xrng64() & 0x604c203e) | 0x16819e01 | bb | (Q[Qoff + 6] & 0x01000000);
		Q[Qoff + 8] = (xrng64() & 0x604c7c1c) | 0x043283e0 | (Q[Qoff + 7] & 0x80000002);
		Q[Qoff + 9] = (xrng64() & 0x00002800) | 0x1c0101c1 | (Q[Qoff + 8] & 0x80001000);
		Q[Qoff + 10] = 0x078bcbc0 | bb;
		Q[Qoff + 11] = (xrng64() & 0x07800000) | 0x607dc7df | bb;
		Q[Qoff + 12] = (xrng64() & 0x00f00f7f) | 0x00081080 | (Q[Qoff + 11] & 0xe7000000);
		Q[Qoff + 13] = (xrng64() & 0x00701f77) | 0x3f0fe008 | aa;
		Q[Qoff + 14] = (xrng64() & 0x00701f77) | 0x408be088 | aa;
		Q[Qoff + 15] = (xrng64() & 0x00ff3ff7) | 0x7d000000;
		Q[Qoff + 16] = (xrng64() & 0x4ffdffff) | 0x20000000 | (~Q[Qoff + 15] & 0x00020000);

		MD5_REVERSE_STEP(5, 0x4787c62a, 12);
		MD5_REVERSE_STEP(6, 0xa8304613, 17);
		MD5_REVERSE_STEP(7, 0xfd469501, 22);
		MD5_REVERSE_STEP(11, 0x895cd7be, 22);
		MD5_REVERSE_STEP(14, 0xa679438e, 17);
		MD5_REVERSE_STEP(15, 0x49b40821, 22);

		const uint32 tt17 = GG(Q[Qoff + 16], Q[Qoff + 15], Q[Qoff + 14]) + Q[Qoff + 13] + 0xf61e2562;
		const uint32 tt18 = Q[Qoff + 14] + 0xc040b340 + block[6];
		const uint32 tt19 = Q[Qoff + 15] + 0x265e5a51 + block[11];

		const uint32 tt0 = FF(Q[Qoff + 0], Q[Qoff - 1], Q[Qoff - 2]) + Q[Qoff - 3] + 0xd76aa478;
		const uint32 tt1 = Q[Qoff - 2] + 0xe8c7b756;

		const uint32 q1a = 0x04200040 | (Q[Qoff + 2] & 0xf01e1080);

		unsigned counter = 0;
		while (counter < (1 << 12))
		{
			++counter;

			uint32 q1 = q1a | (xrng64() & 0x01c0e71f);
			uint32 m1 = Q[Qoff + 2] - q1;
			m1 = RR(m1, 12) - FF(q1, Q[Qoff + 0], Q[Qoff - 1]) - tt1;

			const uint32 q16 = Q[Qoff + 16];
			uint32 q17 = tt17 + m1;
			q17 = RL(q17, 5) + q16;
			if (0x40000000 != ((q17 ^ q16) & 0xc0008008)) continue;
			if (0 != (q17 & 0x00020000)) continue;

			uint32 q18 = GG(q17, q16, Q[Qoff + 15]) + tt18;
			q18 = RL(q18, 9); q18 += q17;
			if (0x00020000 != ((q18 ^ q17) & 0xa0020000)) continue;

			uint32 q19 = GG(q18, q17, q16) + tt19;
			q19 = RL(q19, 14); q19 += q18;
			if (0 != (q19 & 0x80020000)) continue;

			uint32 m0 = q1 - Q[Qoff + 0];
			m0 = RR(m0, 7) - tt0;

			uint32 q20 = GG(q19, q18, q17) + q16 + 0xe9b6c7aa + m0;
			q20 = RL(q20, 20); q20 += q19;
			if (0x00040000 != ((q20 ^ q19) & 0x80040000))	continue;

			Q[Qoff + 1] = q1;
			Q[Qoff + 17] = q17;
			Q[Qoff + 18] = q18;
			Q[Qoff + 19] = q19;
			Q[Qoff + 20] = q20;

			block[0] = m0;
			block[1] = m1;
			MD5_REVERSE_STEP(2, 0x242070db, 17);

			counter = 0;
			break;
		}
		if (counter != 0)
			continue;

		const uint32 q4b = Q[Qoff + 4];
		const uint32 q9b = Q[Qoff + 9];
		const uint32 q10b = Q[Qoff + 10];
		const uint32 tt21 = GG(Q[Qoff + 20], Q[Qoff + 19], Q[Qoff + 18]) + Q[Qoff + 17] + 0xd62f105d;

		counter = 0;
		while (counter < (1 << 6))
		{
			Q[Qoff + 4] = q4b ^ q4mask[counter];
			++counter;
			MD5_REVERSE_STEP(5, 0x4787c62a, 12);
			uint32 q21 = tt21 + block[5];
			q21 = RL(q21, 5); q21 += Q[Qoff + 20];
			if (0 != ((q21 ^ Q[Qoff + 20]) & 0x80020000)) continue;

			Q[Qoff + 21] = q21;
			MD5_REVERSE_STEP(3, 0xc1bdceee, 22);
			MD5_REVERSE_STEP(4, 0xf57c0faf, 7);
			MD5_REVERSE_STEP(7, 0xfd469501, 22);

			const uint32 tt10 = Q[Qoff + 7] + 0xffff5bb1;
			const uint32 tt22 = GG(Q[Qoff + 21], Q[Qoff + 20], Q[Qoff + 19]) + Q[Qoff + 18] + 0x02441453;
			const uint32 tt23 = Q[Qoff + 19] + 0xd8a1e681 + block[15];
			const uint32 tt24 = Q[Qoff + 20] + 0xe7d3fbc8 + block[4];

			unsigned counter2 = 0;
			while (counter2 < (1 << 5))
			{
				uint32 q10 = q10b ^ q10mask[counter2];
				uint32 m10 = RR(Q[Qoff + 11] - q10, 17);
				uint32 q9 = q9b ^ q9mask[counter2];
				++counter2;

				m10 -= FF(q10, q9, Q[Qoff + 8]) + tt10;

				uint32 aa = Q[Qoff + 21];
				uint32 dd = tt22 + m10; dd = RL(dd, 9) + aa;
				if (0 != (dd & 0x80000000)) continue;

				uint32 bb = Q[Qoff + 20];
				uint32 cc = tt23 + GG(dd, aa, bb);
				if (0 != (cc & 0x20000)) continue;
				cc = RL(cc, 14) + dd;
				if (0 != (cc & 0x80000000)) continue;

				bb = tt24 + GG(cc, dd, aa); bb = RL(bb, 20) + cc;
				if (0 == (bb & 0x80000000)) continue;

				block[10] = m10;
				Q[Qoff + 9] = q9;
				Q[Qoff + 10] = q10;
				MD5_REVERSE_STEP(13, 0xfd987193, 12);

				for (unsigned k9 = 0; k9 < (1 << 10);)
				{
					uint32 a = aa, b = bb, c = cc, d = dd;
					Q[Qoff + 9] = q9 ^ q9mask2[k9]; ++k9;
					MD5_REVERSE_STEP(8, 0x698098d8, 7);
					MD5_REVERSE_STEP(9, 0x8b44f7af, 12);
					MD5_REVERSE_STEP(12, 0x6b901122, 7);

					MD5_STEP(GG, a, b, c, d, block[9], 0x21e1cde6, 5);
					MD5_STEP(GG, d, a, b, c, block[14], 0xc33707d6, 9);
					MD5_STEP(GG, c, d, a, b, block[3], 0xf4d50d87, 14);
					MD5_STEP(GG, b, c, d, a, block[8], 0x455a14ed, 20);
					MD5_STEP(GG, a, b, c, d, block[13], 0xa9e3e905, 5);
					MD5_STEP(GG, d, a, b, c, block[2], 0xfcefa3f8, 9);
					MD5_STEP(GG, c, d, a, b, block[7], 0x676f02d9, 14);
					MD5_STEP(GG, b, c, d, a, block[12], 0x8d2a4c8a, 20);
					MD5_STEP(HH, a, b, c, d, block[5], 0xfffa3942, 4);
					MD5_STEP(HH, d, a, b, c, block[8], 0x8771f681, 11);

					c += HH(d, a, b) + block[11] + 0x6d9d6122;
					if (0 == (c & (1 << 15)))
						continue;
					c = (c << 16 | c >> 16) + d;

					MD5_STEP(HH, b, c, d, a, block[14], 0xfde5380c, 23);
					MD5_STEP(HH, a, b, c, d, block[1], 0xa4beea44, 4);
					MD5_STEP(HH, d, a, b, c, block[4], 0x4bdecfa9, 11);
					MD5_STEP(HH, c, d, a, b, block[7], 0xf6bb4b60, 16);
					MD5_STEP(HH, b, c, d, a, block[10], 0xbebfbc70, 23);
					MD5_STEP(HH, a, b, c, d, block[13], 0x289b7ec6, 4);
					MD5_STEP(HH, d, a, b, c, block[0], 0xeaa127fa, 11);
					MD5_STEP(HH, c, d, a, b, block[3], 0xd4ef3085, 16);
					MD5_STEP(HH, b, c, d, a, block[6], 0x04881d05, 23);
					MD5_STEP(HH, a, b, c, d, block[9], 0xd9d4d039, 4);
					MD5_STEP(HH, d, a, b, c, block[12], 0xe6db99e5, 11);
					MD5_STEP(HH, c, d, a, b, block[15], 0x1fa27cf8, 16);
					MD5_STEP(HH, b, c, d, a, block[2], 0xc4ac5665, 23);
					if (0 != ((b ^ d) & 0x80000000))
						continue;

					MD5_STEP(II, a, b, c, d, block[0], 0xf4292244, 6);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, d, a, b, c, block[7], 0x432aff97, 10);
					if (0 == ((b ^ d) >> 31)) continue;
					MD5_STEP(II, c, d, a, b, block[14], 0xab9423a7, 15);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, b, c, d, a, block[5], 0xfc93a039, 21);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, a, b, c, d, block[12], 0x655b59c3, 6);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, d, a, b, c, block[3], 0x8f0ccc92, 10);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, c, d, a, b, block[10], 0xffeff47d, 15);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, b, c, d, a, block[1], 0x85845dd1, 21);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, a, b, c, d, block[8], 0x6fa87e4f, 6);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, d, a, b, c, block[15], 0xfe2ce6e0, 10);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, c, d, a, b, block[6], 0xa3014314, 15);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, b, c, d, a, block[13], 0x4e0811a1, 21);
					if (0 == ((b ^ d) >> 31)) continue;
					MD5_STEP(II, a, b, c, d, block[4], 0xf7537e82, 6);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, d, a, b, c, block[11], 0xbd3af235, 10);
					if (0 != ((b ^ d) >> 31)) continue;
					MD5_STEP(II, c, d, a, b, block[2], 0x2ad7d2bb, 15);
					if (0 != ((a ^ c) >> 31)) continue;
					MD5_STEP(II, b, c, d, a, block[9], 0xeb86d391, 21);

					

					uint32 block2[16];
					uint32 IV1[4], IV2[4];
					for (int t = 0; t < 4; ++t)
					{
						IV1[t] = IV[t];
						IV2[t] = IV[t] + (1 << 31);
					}
					IV2[1] += (1 << 25);
					IV2[2] += (1 << 25);
					IV2[3] += (1 << 25);

					for (int t = 0; t < 16; ++t)
						block2[t] = block[t];
					block2[4] += 1 << 31;
					block2[11] -= 1 << 15;
					block2[14] += 1 << 31;

					md5_compress(IV1, block);
					md5_compress(IV2, block2);
					if (IV2[0] == IV1[0] && IV2[1] == IV1[1] && IV2[2] == IV1[2] && IV2[3] == IV1[3])
						return;

					if (IV2[0] != IV1[0])
						std::cout << "!" << std::flush;
				}
			}
		}
	}
}

unsigned load_block(std::istream& i, uint32 block[])
{
	unsigned len = 0;
	char uc;
	for (unsigned k = 0; k < 16; ++k)
	{
		block[k] = 0;
		for (unsigned c = 0; c < 4; ++c)
		{
			i.get(uc);
			if (i)
				++len;
			else
				uc = 0;
			block[k] += uint32((unsigned char)(uc)) << (c * 8);
		}
	}
	return len;
}

void save_block(std::ostream& o, const uint32 block[])
{
	for (unsigned k = 0; k < 16; ++k)
		for (unsigned c = 0; c < 4; ++c)
			o << (unsigned char)((block[k] >> (c * 8)) & 0xFF);
}

void find_collision(const uint32 IV[], uint32 msg1block0[], uint32 msg1block1[], uint32 msg2block0[], uint32 msg2block1[])
{
	find_block0(msg1block0, IV);

	uint32 IHV[4] = { IV[0], IV[1], IV[2], IV[3] };
	md5_compress(IHV, msg1block0);
	find_block1(msg1block1, IHV);

	for (int t = 0; t < 16; ++t)
	{
		msg2block0[t] = msg1block0[t];
		msg2block1[t] = msg1block1[t];
	}
	msg2block0[4] += 1 << 31; msg2block0[11] += 1 << 15; msg2block0[14] += 1 << 31;
	msg2block1[4] += 1 << 31; msg2block1[11] -= 1 << 15; msg2block1[14] += 1 << 31;
}

void md5collgen(std::string& prefixfn, std::string& outfn1, std::string& outfn2, std::string& ihv)
{
	seed32_1 = uint32(time(NULL));
	seed32_2 = 0x12345678;

	uint32 IV[4] = { MD5IV[0], MD5IV[1], MD5IV[2], MD5IV[3] };

	unsigned l = prefixfn.size();
	std::ofstream ofs1(outfn1.c_str(), std::ios::binary);
	std::ofstream ofs2(outfn2.c_str(), std::ios::binary);
	std::ifstream ifs(prefixfn.c_str(), std::ios::binary);

	uint32 block[16];
	while (true)
	{
		unsigned len = load_block(ifs, block);
		if (len)
		{
			save_block(ofs1, block);
			save_block(ofs2, block);
			md5_compress(IV, block);
		}
		else
			break;
	}

	uint32 msg1block0[16];
	uint32 msg1block1[16];
	uint32 msg2block0[16];
	uint32 msg2block1[16];
	find_collision(IV, msg1block0, msg1block1, msg2block0, msg2block1);
	save_block(ofs1, msg1block0);
	save_block(ofs1, msg1block1);
	save_block(ofs2, msg2block0);
	save_block(ofs2, msg2block1);
}

void md5_compress(uint32 ihv[], const uint32 block[])
{
	uint32 a = ihv[0];
	uint32 b = ihv[1];
	uint32 c = ihv[2];
	uint32 d = ihv[3];

	MD5_STEP(FF, a, b, c, d, block[0], 0xd76aa478, 7);
	MD5_STEP(FF, d, a, b, c, block[1], 0xe8c7b756, 12);
	MD5_STEP(FF, c, d, a, b, block[2], 0x242070db, 17);
	MD5_STEP(FF, b, c, d, a, block[3], 0xc1bdceee, 22);
	MD5_STEP(FF, a, b, c, d, block[4], 0xf57c0faf, 7);
	MD5_STEP(FF, d, a, b, c, block[5], 0x4787c62a, 12);
	MD5_STEP(FF, c, d, a, b, block[6], 0xa8304613, 17);
	MD5_STEP(FF, b, c, d, a, block[7], 0xfd469501, 22);
	MD5_STEP(FF, a, b, c, d, block[8], 0x698098d8, 7);
	MD5_STEP(FF, d, a, b, c, block[9], 0x8b44f7af, 12);
	MD5_STEP(FF, c, d, a, b, block[10], 0xffff5bb1, 17);
	MD5_STEP(FF, b, c, d, a, block[11], 0x895cd7be, 22);
	MD5_STEP(FF, a, b, c, d, block[12], 0x6b901122, 7);
	MD5_STEP(FF, d, a, b, c, block[13], 0xfd987193, 12);
	MD5_STEP(FF, c, d, a, b, block[14], 0xa679438e, 17);
	MD5_STEP(FF, b, c, d, a, block[15], 0x49b40821, 22);
	MD5_STEP(GG, a, b, c, d, block[1], 0xf61e2562, 5);
	MD5_STEP(GG, d, a, b, c, block[6], 0xc040b340, 9);
	MD5_STEP(GG, c, d, a, b, block[11], 0x265e5a51, 14);
	MD5_STEP(GG, b, c, d, a, block[0], 0xe9b6c7aa, 20);
	MD5_STEP(GG, a, b, c, d, block[5], 0xd62f105d, 5);
	MD5_STEP(GG, d, a, b, c, block[10], 0x02441453, 9);
	MD5_STEP(GG, c, d, a, b, block[15], 0xd8a1e681, 14);
	MD5_STEP(GG, b, c, d, a, block[4], 0xe7d3fbc8, 20);
	MD5_STEP(GG, a, b, c, d, block[9], 0x21e1cde6, 5);
	MD5_STEP(GG, d, a, b, c, block[14], 0xc33707d6, 9);
	MD5_STEP(GG, c, d, a, b, block[3], 0xf4d50d87, 14);
	MD5_STEP(GG, b, c, d, a, block[8], 0x455a14ed, 20);
	MD5_STEP(GG, a, b, c, d, block[13], 0xa9e3e905, 5);
	MD5_STEP(GG, d, a, b, c, block[2], 0xfcefa3f8, 9);
	MD5_STEP(GG, c, d, a, b, block[7], 0x676f02d9, 14);
	MD5_STEP(GG, b, c, d, a, block[12], 0x8d2a4c8a, 20);
	MD5_STEP(HH, a, b, c, d, block[5], 0xfffa3942, 4);
	MD5_STEP(HH, d, a, b, c, block[8], 0x8771f681, 11);
	MD5_STEP(HH, c, d, a, b, block[11], 0x6d9d6122, 16);
	MD5_STEP(HH, b, c, d, a, block[14], 0xfde5380c, 23);
	MD5_STEP(HH, a, b, c, d, block[1], 0xa4beea44, 4);
	MD5_STEP(HH, d, a, b, c, block[4], 0x4bdecfa9, 11);
	MD5_STEP(HH, c, d, a, b, block[7], 0xf6bb4b60, 16);
	MD5_STEP(HH, b, c, d, a, block[10], 0xbebfbc70, 23);
	MD5_STEP(HH, a, b, c, d, block[13], 0x289b7ec6, 4);
	MD5_STEP(HH, d, a, b, c, block[0], 0xeaa127fa, 11);
	MD5_STEP(HH, c, d, a, b, block[3], 0xd4ef3085, 16);
	MD5_STEP(HH, b, c, d, a, block[6], 0x04881d05, 23);
	MD5_STEP(HH, a, b, c, d, block[9], 0xd9d4d039, 4);
	MD5_STEP(HH, d, a, b, c, block[12], 0xe6db99e5, 11);
	MD5_STEP(HH, c, d, a, b, block[15], 0x1fa27cf8, 16);
	MD5_STEP(HH, b, c, d, a, block[2], 0xc4ac5665, 23);
	MD5_STEP(II, a, b, c, d, block[0], 0xf4292244, 6);
	MD5_STEP(II, d, a, b, c, block[7], 0x432aff97, 10);
	MD5_STEP(II, c, d, a, b, block[14], 0xab9423a7, 15);
	MD5_STEP(II, b, c, d, a, block[5], 0xfc93a039, 21);
	MD5_STEP(II, a, b, c, d, block[12], 0x655b59c3, 6);
	MD5_STEP(II, d, a, b, c, block[3], 0x8f0ccc92, 10);
	MD5_STEP(II, c, d, a, b, block[10], 0xffeff47d, 15);
	MD5_STEP(II, b, c, d, a, block[1], 0x85845dd1, 21);
	MD5_STEP(II, a, b, c, d, block[8], 0x6fa87e4f, 6);
	MD5_STEP(II, d, a, b, c, block[15], 0xfe2ce6e0, 10);
	MD5_STEP(II, c, d, a, b, block[6], 0xa3014314, 15);
	MD5_STEP(II, b, c, d, a, block[13], 0x4e0811a1, 21);
	MD5_STEP(II, a, b, c, d, block[4], 0xf7537e82, 6);
	MD5_STEP(II, d, a, b, c, block[11], 0xbd3af235, 10);
	MD5_STEP(II, c, d, a, b, block[2], 0x2ad7d2bb, 15);
	MD5_STEP(II, b, c, d, a, block[9], 0xeb86d391, 21);

	ihv[0] += a;
	ihv[1] += b;
	ihv[2] += c;
	ihv[3] += d;
}

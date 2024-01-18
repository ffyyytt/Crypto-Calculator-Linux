#pragma once
#ifndef _SHA1_H
#define _SHA1_H

#include "md5.h"

class sha1: public Hash
{
private:
		uint32 total[2];
		uint32 state[5];
		uint8 buffer[64];
		void transform(uint8 data[64]);
public:
		static const unsigned int DIGEST_SIZE = 20;
		static const unsigned int BLOCK_SIZE = 64;
		unsigned int getDigestSize() { return DIGEST_SIZE; };
		unsigned int getBlockSize() { return BLOCK_SIZE; };
		void setState(int position, uint64 value);
		void setBuffer(int position, uint8 value);
		uint64 getState(int position);
		uint8 getBuffer(int position);
		void set_m(unsigned int _m_tot_len, unsigned int _m_len);

	void init(uint32 s0 = 0x67452301, uint32 s1 = 0xEFCDAB89, uint32 s2 = 0x98BADCFE, 
			uint32 s3 = 0x10325476, uint32 s4 = 0xC3D2E1F0);
	void update(uint8 * input, uint32 length);
	void final(uint8* digest);
	void assign(uint8* digest);
};

#endif /* sha1.h */

#pragma once
#define _CRT_SECURE_NO_WARNINGS
#ifndef _MD5_H
#define _MD5_H
#include <stdio.h>
#include <cstdint>
#include <iostream>

#ifndef uint8
#define uint8 unsigned char
#endif

#ifndef uint32
#define uint32 uint32_t
#endif

#ifndef uint64
#define uint64 unsigned long long
#endif

class Hash
{
public:
	virtual void init() {};
	virtual void update(uint8* input, unsigned int len) {};
	virtual void final(uint8* digest) {};
	virtual unsigned int getDigestSize() { return 0; };
	virtual unsigned int getBlockSize() { return 0; };
	virtual void assign(uint8* digest) {};
	virtual void setState(int position, uint64 value) {};
	virtual void setBuffer(int position, uint8 value) {};
	virtual uint64 getState(int position) { return 0; };
	virtual uint8 getBuffer(int position) { return 0; };
	virtual void set_m(unsigned int _m_tot_len, unsigned int _m_len) {};
	virtual unsigned int get_m_tot_len(unsigned int value) { return 0; };
	virtual unsigned int get_m_len(unsigned int value) { return 0; };
	static void bytesToHex(uint8* str, int n, char* output);
};

class md5 : public Hash
{
private:
	void transform(uint8 data[64]);
	uint32 total[2];
	uint32 state[5];
	uint8 buffer[64];
public:
	static const unsigned int DIGEST_SIZE = 16;
	static const unsigned int BLOCK_SIZE = 64;
	unsigned int getDigestSize() { return DIGEST_SIZE; };
	unsigned int getBlockSize() { return BLOCK_SIZE; };
	void setState(int position, uint64 value);
	void setBuffer(int position, uint8 value);
	uint64 getState(int position);
	uint8 getBuffer(int position);
	void set_m(unsigned int _m_tot_len, unsigned int _m_len);

	void init(uint32 s0 = 0x67452301, uint32 s1 = 0xEFCDAB89, uint32 s2 = 0x98BADCFE, uint32 s3 = 0x10325476);
	void update(uint8* input, uint32 length);
	void final(uint8* digest);
	void assign(uint8* digest);
};

#endif /* md5.h */

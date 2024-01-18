#pragma once
#ifndef _SHA2_H
#define _SHA2_H

#include "sha1.h"

class sha256 : public virtual  Hash
{
public:
    const static uint32 sha256_k[];
    static const unsigned int DIGEST_SIZE = (256 / 8);
    static const unsigned int SHA224_256_BLOCK_SIZE = (512 / 8);

    unsigned int getDigestSize() { return DIGEST_SIZE; };
    unsigned int getBlockSize() { return 64; };
    void setState(int position, uint64 value);
    void setBuffer(int position, uint8 value);
    uint64 getState(int position);
    uint8 getBuffer(int position);
    void set_m(unsigned int _m_tot_len, unsigned int _m_len);
    unsigned int get_m_tot_len();
    unsigned int get_m_len();

    void init(uint32 s0 = 0x6a09e667, uint32 s1 = 0xbb67ae85, uint32 s2 = 0x3c6ef372, uint32 s3 = 0xa54ff53a,
        uint32 s4 = 0x510e527f, uint32 s5 = 0x9b05688c, uint32 s6 = 0x1f83d9ab, uint32 s7 = 0x5be0cd19);
    void update(uint8* message, unsigned int len);
    void final(uint8* digest);
    void assign(uint8* digest);

    void transform(uint8* message, unsigned int block_nb);
    unsigned int m_tot_len;
    unsigned int m_len;
    uint8 buffer[2 * SHA224_256_BLOCK_SIZE];
    uint32 state[8];
};

class sha224 : public sha256
{
public:
    static const unsigned int DIGEST_SIZE = (224 / 8);
    unsigned int getDigestSize() { return DIGEST_SIZE; };
    unsigned int getBlockSize() { return 64; };

    void init(uint32 s0 = 0xc1059ed8, uint32 s1 = 0x367cd507, uint32 s2 = 0x3070dd17, uint32 s3 = 0xf70e5939,
        uint32 s4 = 0xffc00b31, uint32 s5 = 0x68581511, uint32 s6 = 0x64f98fa7, uint32 s7 = 0xbefa4fa4);
    void update(uint8* message, unsigned int len);
    void final(uint8* digest);
    
};

class sha512 : public Hash
{
public:
    const static uint64 sha512_k[];
    static const unsigned int DIGEST_SIZE = (512 / 8);
    static const unsigned int SHA384_512_BLOCK_SIZE = (1024 / 8);

    unsigned int getDigestSize() { return DIGEST_SIZE; };
    unsigned int getBlockSize() { return 128; };
    void setState(int position, uint64 value);
    void setBuffer(int position, uint8 value);
    uint64 getState(int position);
    uint8 getBuffer(int position);
    void set_m(unsigned int _m_tot_len, unsigned int _m_len);
    unsigned int get_m_tot_len();
    unsigned int get_m_len();

    void init(uint64 s0=0x6a09e667f3bcc908ULL, uint64 s1=0xbb67ae8584caa73bULL, uint64 s2=0x3c6ef372fe94f82bULL,
        uint64 s3=0xa54ff53a5f1d36f1ULL, uint64 s4=0x510e527fade682d1ULL, uint64 s5=0x9b05688c2b3e6c1fULL,
        uint64 s6=0x1f83d9abfb41bd6bULL, uint64 s7=0x5be0cd19137e2179ULL);
    void update(uint8* message, unsigned int len);
    void final(uint8* digest);
    void assign(uint8* digest);

protected:
    void transform(uint8* message, unsigned int block_nb);
    unsigned int m_tot_len;
    unsigned int m_len;
    uint8 buffer[2 * SHA384_512_BLOCK_SIZE];
    uint64 state[8];
};

class sha384 : public sha512
{
public:
    static const unsigned int DIGEST_SIZE = (384 / 8);
    unsigned int getDigestSize() { return DIGEST_SIZE; };
    unsigned int getBlockSize() { return 128; };

    void init(uint64 s0 = 0xcbbb9d5dc1059ed8ULL, uint64 s1 = 0x629a292a367cd507ULL, uint64 s2 = 0x9159015a3070dd17ULL,
        uint64 s3 = 0x152fecd8f70e5939ULL, uint64 s4 = 0x67332667ffc00b31ULL, uint64 s5 = 0x8eb44a8768581511ULL,
        uint64 s6 = 0xdb0c2e0d64f98fa7ULL, uint64 s7 = 0x47b5481dbefa4fa4ULL);
    void update(uint8* message, unsigned int len);
    void final(uint8* digest);
};

#endif /* sha2.h */
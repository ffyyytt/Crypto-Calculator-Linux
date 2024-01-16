#define _CRT_SECURE_NO_WARNINGS
#include "md5.h"
#include "aes.h"
#include "crc.h"
#include "sha1.h"
#include "sha2.h"
#include "base64.h"
#include "md5collgen.h"
#include <iostream>

uint64 padding(unsigned char* message, uint64 length)
{
    uint64 oldLength = length;
    message[length++] = 0x80;
    while (length % 64 != 56)
        message[length++] = 0x00;
    uint64_t bitLength = oldLength * 8;
    for (int i = 7; i >= 0; i--)
        message[length++] = static_cast<uint8_t>((bitLength >> (i * 8)) & 0xFF);
    return length;
}

// hash length extension attack for sha512, sha256, md5, sha1
void hashLengthExtensionAttack(Hash& ctx, std::vector<unsigned long long> digest, unsigned char* extraMessage, unsigned int messageLen, int n_blocks = 1)
{
    char output[100];
    unsigned char hashsum[100];
    ctx.init();
    for (int i = 0; i < 8; i++)
    {
        ctx.setState(i, digest[i]);
    }
    for (unsigned int i = 0; i < ctx.getBlockSize(); i++)
    {
        if (i < messageLen)
            ctx.setBuffer(i, extraMessage[i]);
        else
            ctx.setBuffer(i, '\0');
    }
    ctx.set_m_tot_len(ctx.getBlockSize() * n_blocks);
    ctx.set_m_len(messageLen);
    ctx.final(hashsum);
    for (unsigned int j = 0; j < sha256::DIGEST_SIZE; j++)
    {
        sprintf(output + j * 2, "%02x", hashsum[j]);
    }
    std::cout << output << std::endl;
}

int main()
{
    static char msg[] = "123456:myname=ffyytt&uid=1001&lstcmd=1";
    static char msg1[] = "&download=secret.txt";
    static char key[] = "ABCDEFGHIJKLMNOP";
    char output[100], newmsg[100];
    
    md5 md5_ctx = md5();
    uint8 md5sum[md5::DIGEST_SIZE];
    md5_ctx.init();
    md5_ctx.update((uint8*)msg, strlen(msg));
    md5_ctx.final(md5sum);
    for (unsigned int j = 0; j < md5::DIGEST_SIZE; j++)
    {
        sprintf(output + j * 2, "%02x", md5sum[j]);
    }
    std::cout << output << std::endl;

    sha1 sha1_ctx;
    uint8 sha1sum[sha1::DIGEST_SIZE];
    sha1_ctx.init();
    sha1_ctx.update((uint8*)msg, strlen(msg));
    sha1_ctx.final(sha1sum);
    for (unsigned int j = 0; j < sha1::DIGEST_SIZE; j++)
    {
        sprintf(output + j * 2, "%02x", sha1sum[j]);
    }
    std::cout << output << std::endl;

    sha256 sha256_ctx;
    uint8 sha256sum[sha256::DIGEST_SIZE];
    sha256_ctx.init();
    sha256_ctx.update((uint8*)msg, strlen(msg));
    sha256_ctx.final(sha256sum);
    for (unsigned int j = 0; j < sha256::DIGEST_SIZE; j++)
    {
        sprintf(output + j * 2, "%02x", sha256sum[j]);
    }
    std::cout << output << std::endl;
    //c7ac037d5e6cd43ab7ef47b7fb48f1e7e735f5b7f668178fb8b74c127ea0949f

    // 123456 is password (unknown to the attacker)
    // myname=ffyytt&uid=1001&lstcmd=1&mac=c7ac037d5e6cd43ab7ef47b7fb48f1e7e735f5b7f668178fb8b74c127ea0949f is query 
    // where myname=ffyytt&uid=1001&lstcmd=1 is realquery from user
    // mac = sha256(key:realquery) (server provided to user) = c7ac037d5e6cd43ab7ef47b7fb48f1e7e735f5b7f668178fb8b74c127ea0949f
    // myname=ffyytt&uid=1001&lstcmd=1%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%01%30&download=secret.txt&mac=085b64794c6f2746a9660f1c5e9457699c38e5d78c43ee71d0d74eebe318e1c4 is new_query
    // where download=secret.txt is in query
    // new_query = realquery + pad + extra_message
    // mac = sha256(new_query) = hashLengthExtensionAttack (without key)

    std::vector<unsigned long long> digest;
    digest.push_back(0xc7ac037d);
    digest.push_back(0x5e6cd43a);
    digest.push_back(0xb7ef47b7);
    digest.push_back(0xfb48f1e7);
    digest.push_back(0xe735f5b7);
    digest.push_back(0xf668178f);
    digest.push_back(0xb8b74c12);
    digest.push_back(0x7ea0949f);
    sha256 h;
    hashLengthExtensionAttack(h, digest, (unsigned char*)msg1, strlen(msg1));

    // Check
    strcpy(newmsg, msg);
    uint64 len = padding((uint8*)newmsg, strlen(msg));
    strcpy(&newmsg[len], msg1);
    len += strlen(msg1);
    sha256_ctx.init();
    sha256_ctx.update((uint8*)newmsg, len);
    sha256_ctx.final(sha256sum);
    for (unsigned int j = 0; j < sha256::DIGEST_SIZE; j++)
    {
        sprintf(output + j * 2, "%02x", sha256sum[j]);
    }
    std::cout << output << std::endl;

    AES aes(AESKeyLength::AES_128);
    uint8* msgpad = AES::pkcs7_padding((uint8*)msg, strlen(msg));
    uint8* aesoutput = aes.EncryptECB((uint8*)msgpad, AES::pkcs7_padding_length(strlen(msg)), (uint8*)key);
    std::cout << base64().base64_encode(aesoutput, AES::pkcs7_padding_length(strlen(msg))) << std::endl;
    std::cout << base64().base64_encode((uint8*)msg, strlen(msg)) << std::endl;

    
    AES squareAES(AESKeyLength::SQUARE);
    squareAES.generatePlainTextForSquareAttack("plaintexts.txt");
    squareAES.EncryptListInFile("plaintexts.txt", "ciphertexts.txt", 16 * 256, (uint8*)key);
    unsigned char squarekey[] = "AAAAAAAAAAAAAAAA";
    AES::squareAttack("ciphertexts.txt", squarekey);
    std::cout << squarekey << std::endl;

    std::string prefixfn("prefix.txt");
    std::string outfn1("out1.bin");
    std::string outfn2("out2.bin");
    std::string defaultIV("0123456789abcdeffedcba9876543210");
    md5collgen(prefixfn, outfn1, outfn2, defaultIV);

    std::cout << crc::crc32buf(msg, strlen(msg));

    return 0;
}
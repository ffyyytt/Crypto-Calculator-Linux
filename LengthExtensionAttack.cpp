#include "LengthExtensionAttack.h"
#include <iostream>

uint64 LengthExtensionAttack::padding(unsigned char* message, uint64 length, unsigned int blockSize)
{
    uint64 oldLength = length;
    message[length++] = 0x80;
    while (length % blockSize != (blockSize-8))
        message[length++] = 0x00;
    uint64_t bitLength = oldLength * 8;
    for (int i = 7; i >= 0; i--)
        message[length++] = static_cast<uint8_t>((bitLength >> (i * 8)) & 0xFF);
    return length;
}

void LengthExtensionAttack::hashLengthExtensionAttack(Hash& ctx, uint8* digest, unsigned char* extraMessage, int messageLen, uint8* output, int n_blocks)
{
    ctx.init();
    ctx.assign(digest);
    for (int i = 0; i < ctx.getBlockSize(); i++)
    {
        if (i < messageLen)
            ctx.setBuffer(i, extraMessage[i]);
        else
            ctx.setBuffer(i, '\0');
    }
    ctx.set_m(ctx.getBlockSize() * n_blocks, messageLen);
    ctx.final(output);
}
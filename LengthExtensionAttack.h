#pragma once
#define _CRT_SECURE_NO_WARNINGS
#ifndef _LengthExtensionAttack_H
#define _LengthExtensionAttack_H

#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include <string>

// hash length extension attack for sha512, sha256, md5, sha1
class LengthExtensionAttack
{
public:
	static uint64 padding(unsigned char* message, uint64 length, unsigned int blockSize);
	static void hashLengthExtensionAttack(Hash& ctx, uint8* digest, unsigned char* extraMessage, int messageLen, uint8* output, int n_blocks = 1);
};

#endif /* LengthExtensionAttack.h */

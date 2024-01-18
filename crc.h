#pragma once
#ifndef _CRC_H
#define _CRC_H

#include "md5.h"

class crc
{
public:
	const static uint32 crc_32_tab[];
	static uint32 UPDC32(uint8 b, uint32 c);
	static uint32 updateCRC32(register unsigned char ch, register uint32 crc);
	static uint32 crc32buf(char* buf, size_t len);
};

#endif /* crc.h */
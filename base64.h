#pragma once
#ifndef _BASE64_H
#define _BASE64_H
#include <string>
#include <algorithm>
class base64
{
public:
	std::string base64_decode(std::string const& s, bool remove_linebreaks = false);
	std::string base64_encode(unsigned char const*, size_t len, bool url = false);
};

#endif /* base64.h */
main: aes.h aes.cpp base64.h base64.cpp crc.h crc.cpp md5.h md5.cpp md5collgen.h md5collgen.cpp sha1.h sha1.cpp sha2.h sha2.cpp LengthExtensionAttack.h LengthExtensionAttack.cpp main.cpp
	g++ -o main main.cpp aes.cpp base64.cpp crc.cpp md5.cpp md5collgen.cpp sha1.cpp sha2.cpp LengthExtensionAttack.cpp
clean:
	rm main

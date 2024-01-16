#include "aes.h"

AES::AES(const AESKeyLength keyLength) {
    switch (keyLength) {
    case AESKeyLength::AES_128:
        this->Nk = 4;
        this->Nr = 10;
        break;
    case AESKeyLength::AES_192:
        this->Nk = 6;
        this->Nr = 12;
        break;
    case AESKeyLength::AES_256:
        this->Nk = 8;
        this->Nr = 14;
        break;
    case AESKeyLength::SQUARE:
        this->Nk = 4;
        this->Nr = 4;
        break;
    }
}

void AES::EncryptListInFile(const char inputFileName[], const char outputFileName[], int n, const unsigned char key[])
{
    std::vector<unsigned char> vectorKey;
    for (int i = 0; i < blockBytesLen; i++)
        vectorKey.push_back(key[i]);

    std::fstream inputFile(inputFileName, std::ios_base::in);
    std::fstream outputFile(outputFileName, std::ios_base::out);
    for (int j = 0; j < n; j++)
    {
        std::vector<unsigned char> plaintext;
        int c = 0;
        for (int k = 0; k < 16; k++)
        {
            inputFile >> c;
            plaintext.push_back(c);
        }
        std::vector<unsigned char> ciphertext = EncryptECB(plaintext, vectorKey);
        for (int k = 0; k < 16; k++)
        {
            outputFile << (int) ciphertext[k] << " ";
        }
        outputFile << std::endl;
    }
}

unsigned char* AES::EncryptECB(const unsigned char in[], unsigned int inLen,
    const unsigned char key[]) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::DecryptECB(const unsigned char in[], unsigned int inLen,
    const unsigned char key[]) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        DecryptBlock(in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::EncryptCBC(const unsigned char in[], unsigned int inLen,
    const unsigned char key[],
    const unsigned char* iv) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        XorBlocks(block, in + i, block, blockBytesLen);
        EncryptBlock(block, out + i, roundKeys);
        memcpy(block, out + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::DecryptCBC(const unsigned char in[], unsigned int inLen,
    const unsigned char key[],
    const unsigned char* iv) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        DecryptBlock(in + i, out + i, roundKeys);
        XorBlocks(block, out + i, out + i, blockBytesLen);
        memcpy(block, in + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::EncryptCFB(const unsigned char in[], unsigned int inLen,
    const unsigned char key[],
    const unsigned char* iv) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char encryptedBlock[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock(block, encryptedBlock, roundKeys);
        XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(block, out + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char* AES::DecryptCFB(const unsigned char in[], unsigned int inLen,
    const unsigned char key[],
    const unsigned char* iv) {
    CheckLength(inLen);
    unsigned char* out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char encryptedBlock[blockBytesLen];
    unsigned char* roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, roundKeys);
    memcpy(block, iv, blockBytesLen);
    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock(block, encryptedBlock, roundKeys);
        XorBlocks(in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy(block, in + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

void AES::CheckLength(unsigned int len) {
    if (len % blockBytesLen != 0) {
        throw std::length_error("Plaintext length must be divisible by " +
            std::to_string(blockBytesLen));
    }
}

unsigned char* AES::pkcs7_padding(unsigned char* in, unsigned int inLen, unsigned int modulus)
{
    unsigned char* out = new unsigned char[pkcs7_padding_length(inLen)+1];
    memcpy(out, in, inLen * sizeof(unsigned char));
    unsigned int pad_byte = modulus - (inLen % modulus);
    for (int i = 0; i < pad_byte; i++) {
        out[inLen + i] = pad_byte;
    }
    return out;
}

unsigned int AES::pkcs7_padding_length(unsigned int inLen, unsigned int modulus)
{
    return std::ceil((inLen+.0) / blockBytesLen) * blockBytesLen;
}

void AES::getFirstKey(const unsigned char key[], unsigned char firstKey[], int round)
{
    std::vector<std::vector<unsigned char>> vectorKeys;
    for (int i = 0; i < blockBytesLen / 4; i++)
    {
        std::vector<unsigned char> vectorKey;
        for (int j = 0; j < 4; j++) 
            vectorKey.push_back(key[i * 4 + j]);
        vectorKeys.push_back(vectorKey);
    }
    for (int i = round; i > 0; i--)
    {
        for (int j = 0; j < 3; j++)
        {
            std::vector<unsigned char> vectorKey(vectorKeys[0]);
            XorWords(vectorKeys[2].data(), vectorKeys[3].data(), vectorKey.data());
            vectorKeys.insert(vectorKeys.begin(), vectorKey);
        }
        std::vector<unsigned char> vectorKey(vectorKeys[0]);
        std::vector<unsigned char> vectorKey0(vectorKeys[2]);
        std::vector<unsigned char> vectorKey1(vectorKeys[0]);
        std::vector<unsigned char> rcon(vectorKeys[0]);
        RotWord(vectorKey0.data());
        SubWord(vectorKey0.data());
        Rcon(rcon.data(), i);
        XorWords(vectorKeys[3].data(), rcon.data(), vectorKey1.data());
        XorWords(vectorKey1.data(), vectorKey0.data(), vectorKey.data());
        vectorKeys.insert(vectorKeys.begin(), vectorKey);
    }
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            firstKey[i * 4 + j] = vectorKeys[i][j];
        }
    }
}

unsigned char AES::findKey(int position, std::vector<std::vector<std::vector<unsigned char>>> ciphertexts)
{
    for (int i = 0; i < blockBytesLen; i++)
    {
        std::vector<int> correct_guesses;
        std::vector<std::vector<unsigned char>> ciphertext = ciphertexts[i];
        for (int guess = 0; guess < 256; guess++)
        {
            int r = 0;
            for (int j = 0; j < 256; j++)
            {
                std::vector<unsigned char> s = ciphertext[j];
                unsigned char before_add_round_key = s[position] ^ (unsigned char)guess;
                unsigned char before_sub_byte = inv_sbox[before_add_round_key / blockBytesLen][before_add_round_key % blockBytesLen];
                r ^= before_sub_byte;
            }
            if (r == 0)
                correct_guesses.push_back(guess);
        }
        if (correct_guesses.size() == 1)
            return correct_guesses[0];
    }
    return 0;
}

void AES::squareAttack(const char filename[], unsigned char key[])
{
    unsigned char lastKey[blockBytesLen];
    std::ifstream file(filename);
    std::vector<std::vector<std::vector<unsigned char>>> ciphertexts;
    for (int i = 0; i < blockBytesLen; i++)
    {
        std::vector<std::vector<unsigned char>> ciphertext;
        for (int j = 0; j < 256; j++)
        {
            std::vector<unsigned char> s;
            int c = 0;
            for (int k = 0; k < blockBytesLen; k++)
            {
                file >> c;
                s.push_back(c);
            }
            ciphertext.push_back(s);
        }
        ciphertexts.push_back(ciphertext);
    }

    for (int position = 0; position < blockBytesLen; position++)
    {
        lastKey[position] = findKey(position, ciphertexts);
    }
    getFirstKey(lastKey, key, 4);
}

void AES::generatePlainTextForSquareAttack(const char filename[])
{
    std::fstream outputFile(filename, std::ios_base::out);
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 256; j++)
        {
            outputFile << j;
            for (int k = 0; k < 15;k++)
            {
                outputFile << " " << i;
            }
            outputFile << std::endl;
        }
    }
}

void AES::EncryptBlock(const unsigned char in[], unsigned char out[],
    unsigned char* roundKeys) {
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys);

    for (round = 1; round <= Nr - 1; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void AES::DecryptBlock(const unsigned char in[], unsigned char out[],
    unsigned char* roundKeys) {
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, roundKeys + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--) {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, roundKeys + round * 4 * Nb);
        InvMixColumns(state);
    }

    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void AES::SubBytes(unsigned char state[4][Nb]) {
    unsigned int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }
}

void AES::ShiftRow(unsigned char state[4][Nb], unsigned int i,
    unsigned int n)  // shift row i on n positions
{
    unsigned char tmp[Nb];
    for (unsigned int j = 0; j < Nb; j++) {
        tmp[j] = state[i][(j + n) % Nb];
    }
    memcpy(state[i], tmp, Nb * sizeof(unsigned char));
}

void AES::ShiftRows(unsigned char state[4][Nb]) {
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b)  // multiply on x
{
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void AES::MixColumns(unsigned char state[4][Nb]) {
    unsigned char temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                if (CMDS[i][k] == 1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void AES::AddRoundKey(unsigned char state[4][Nb], unsigned char* key) {
    unsigned int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}

void AES::SubWord(unsigned char* a) {
    int i;
    for (i = 0; i < 4; i++) {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void AES::RotWord(unsigned char* a) {
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void AES::XorWords(unsigned char* a, unsigned char* b, unsigned char* c) {
    int i;
    for (i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::Rcon(unsigned char* a, unsigned int n) {
    unsigned int i;
    unsigned char c = 1;
    for (i = 0; i < n - 1; i++) {
        c = xtime(c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(const unsigned char key[], unsigned char w[]) {
    unsigned char temp[4];
    unsigned char rcon[4];

    unsigned int i = 0;
    while (i < 4 * Nk) {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / (Nk * 4));
            XorWords(temp, rcon, temp);
        }
        else if (Nk > 6 && i / 4 % Nk == 4) {
            SubWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }
}

void AES::InvSubBytes(unsigned char state[4][Nb]) {
    unsigned int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

void AES::InvMixColumns(unsigned char state[4][Nb]) {
    unsigned char temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void AES::InvShiftRows(unsigned char state[4][Nb]) {
    ShiftRow(state, 1, Nb - 1);
    ShiftRow(state, 2, Nb - 2);
    ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(const unsigned char* a, const unsigned char* b,
    unsigned char* c, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::printHexArray(unsigned char a[], unsigned int n) {
    for (unsigned int i = 0; i < n; i++) {
        printf("%02x ", a[i]);
    }
}

void AES::printHexVector(std::vector<unsigned char> a) {
    for (unsigned int i = 0; i < a.size(); i++) {
        printf("%02x ", a[i]);
    }
}

std::vector<unsigned char> AES::ArrayToVector(unsigned char* a,
    unsigned int len) {
    std::vector<unsigned char> v(a, a + len * sizeof(unsigned char));
    return v;
}

unsigned char* AES::VectorToArray(std::vector<unsigned char>& a) {
    return a.data();
}

std::vector<unsigned char> AES::EncryptECB(std::vector<unsigned char> in,
    std::vector<unsigned char> key) {
    unsigned char* out = EncryptECB(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key));
    std::vector<unsigned char> v = ArrayToVector(out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptECB(std::vector<unsigned char> in,
    std::vector<unsigned char> key) {
    unsigned char* out = DecryptECB(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::EncryptCBC(std::vector<unsigned char> in,
    std::vector<unsigned char> key,
    std::vector<unsigned char> iv) {
    unsigned char* out = EncryptCBC(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptCBC(std::vector<unsigned char> in,
    std::vector<unsigned char> key,
    std::vector<unsigned char> iv) {
    unsigned char* out = DecryptCBC(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::EncryptCFB(std::vector<unsigned char> in,
    std::vector<unsigned char> key,
    std::vector<unsigned char> iv) {
    unsigned char* out = EncryptCFB(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptCFB(std::vector<unsigned char> in,
    std::vector<unsigned char> key,
    std::vector<unsigned char> iv) {
    unsigned char* out = DecryptCFB(VectorToArray(in), (unsigned int)in.size(),
        VectorToArray(key), VectorToArray(iv));
    std::vector<unsigned char> v = ArrayToVector(out, (unsigned int)in.size());
    delete[] out;
    return v;
}

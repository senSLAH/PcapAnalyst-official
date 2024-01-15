//
// Created by Illia Aldabaiev on 19/10/2023.
//

#include "EncryptorDecryptor.h"

#include <iostream>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <string>
#include <random>
#include <algorithm>


void EncryptorDecryptor::encrypString(std::string textStr)
{
    auto len = 0;
    auto textLen = textStr.length();
    auto* text = (unsigned char*)textStr.c_str();
    auto keyString = generateRandom16DigitKey();
    auto* key = (unsigned char *) keyString.c_str();
    int encryptedTextLength = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Determine the maximum possible size for the encrypted data
    auto max_encrypt_size = textLen + EVP_MAX_BLOCK_LENGTH; // EVP_MAX_BLOCK_LENGTH is the maximum block size for an encryption algorithm

    encryptText_.resize(max_encrypt_size);

    if(!ctx)
    {
        perror("EVP_CIPHER_CTX_new error");
        exit(1);
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
    {
        perror("EVP_EncryptInit_ex error");
        exit(1);
    }

    if(!EVP_EncryptUpdate(ctx, encryptText_.data(), &len, text, textLen))
    {
        perror("EVP_EncryptUpdate error");
        exit(1);
    }

    encryptedTextLength += len;

    if (!EVP_EncryptFinal_ex(ctx, encryptText_.data() + len, &len))
    {
        perror("EVP_EncryptFinal_ex error");
        exit(1);
    }

    encryptedTextLength += len;

    EVP_CIPHER_CTX_free(ctx);

    encryptText_.resize(encryptedTextLength);

    std::cout << "Your key = " << keyString << std::endl;

}

void EncryptorDecryptor::decryptString()
{
    auto keyStr = std::string{};
    std::cout << "Enter key: ";
    std::cin >> keyStr;

    const auto cipherLen = encryptText_.size();
    auto* key = stringToHex(keyStr);
    auto textLen = 0;
    auto len = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    decryptedText_.resize(cipherLen);

    if(!ctx)
    {
        perror("EVP_CIPHER_CTX_new error");
        exit(1);
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
    {
        perror("EVP_DecryptInit_ex error");
        exit(1);
    }

    if(!EVP_DecryptUpdate(ctx, decryptedText_.data(), &len, encryptText_.data(), cipherLen))
    {
        perror("EVP_DecryptUpdate error");
        exit(1);
    }

    textLen += len;

    if (!EVP_DecryptFinal_ex(ctx, decryptedText_.data() + len, &len))
    {
        perror("EVP_DecryptFinal_ex error");
        exit(1);
    }

    textLen += len;

    EVP_CIPHER_CTX_free(ctx);

    decryptedText_.resize(textLen);
}

void EncryptorDecryptor::printEncryptedText() const
{
    std::cout << "\ncipher = ";
    for (const auto& i : encryptText_)
    {
        printf("%02x ", i);
    }
    std::cout << "\n";
}

std::string EncryptorDecryptor::getEncryptedText() const
{
    auto encryptedTextStr = std::string{};
    for (const auto& i : encryptText_)
    {
        encryptedTextStr += i;
    }
    return encryptedTextStr;
}

void EncryptorDecryptor::printDecryptedText() const
{
    std::cout << "\ndecrypted text = ";
    for (const auto& i : decryptedText_)
    {
        printf("%c", (const char)i);
    }
    std::cout << std::endl;
}

std::string EncryptorDecryptor::generateRandom16DigitKey()
{
    std::string str("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    std::random_device rd;
    std::mt19937 generator(rd());

    std::shuffle(str.begin(), str.end(), generator);

    auto randomString = str.substr(0, 16);

    return randomString.c_str();
}

unsigned char* EncryptorDecryptor::stringToHex(std::string stringKey)
{
    auto key = (unsigned char *) stringKey.c_str();
    return key;
}

void EncryptorDecryptor::resetClass()
{
    encryptText_.clear();
    decryptedText_.clear();
}

void EncryptorDecryptor::setEncryptedText(std::string encryptedText)
{
    auto encryptedTextVec = std::vector<unsigned char>{};
    for (const auto& i : encryptedText)
    {
        encryptedTextVec.push_back(i);
    }
    encryptText_ = encryptedTextVec;
    encryptText_.pop_back();
}


//
// Created by Illia Aldabaiev on 24/10/2023.
//

#include "ComputeSHA256.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/sha.h>
#include <openssl/evp.h>

ComputeSHA256::ComputeSHA256()
{}

void ComputeSHA256::computeAndPrintSHA256(const std::string filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file." << std::endl;
    }
    // generate hash 256 of file using openssl EVP
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    const int bufSize = 32768;
    char* buffer = new char[bufSize];
    while (file.good()) {
        file.read(buffer, bufSize);
        EVP_DigestUpdate(mdctx, buffer, file.gcount());
    }
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    delete[] buffer;

    // convert hash to string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < hash_len; i++) {
        ss << std::setw(2) << (int)hash[i];
    }

    std::cout << "SHA256 hashsum: " << ss.str() << std::endl;
}



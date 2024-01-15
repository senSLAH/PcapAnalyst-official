//
// Created by Illia Aldabaiev on 19/10/2023.
//

#ifndef PCAPANALYST_ENCRYPTORDECRYPTOR_H
#define PCAPANALYST_ENCRYPTORDECRYPTOR_H

#include <fstream>
#include <vector>

class EncryptorDecryptor {
    std::vector<unsigned char> encryptText_;
    std::vector<unsigned char> decryptedText_;

public:
    void encrypString(std::string textStr);
    void decryptString();
    void setEncryptedText(std::string encryptedText);
    std::string getEncryptedText() const;
    std::string getDecryptedText() const;
    static unsigned char* stringToHex(std::string stringKey);
    void printEncryptedText() const;
    void printDecryptedText() const;
    void resetClass();
    static std::string generateRandom16DigitKey();

};

#endif //PCAPANALYST_ENCRYPTORDECRYPTOR_H

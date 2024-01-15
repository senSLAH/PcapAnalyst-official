//
// Created by Illia Aldabaiev on 24/10/2023.
//

#ifndef PCAPANALYST_COMPUTESHA256_H
#define PCAPANALYST_COMPUTESHA256_H

#include <string>

class ComputeSHA256
{
public:
    ComputeSHA256();
    static void computeAndPrintSHA256(const std::string filename);
};


#endif //PCAPANALYST_COMPUTESHA256_H

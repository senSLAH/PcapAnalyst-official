//
// Created by Ilya Aldabaev on 18/10/2023.
//

#ifndef PCAPANALYST_PROGRAMCONTROLLER_H
#define PCAPANALYST_PROGRAMCONTROLLER_H


#include "../PcapFileReader/PcapFileReader.h"
#include "../FileCreator/FileCreator.h"
#include "../EncryptorDecryptor/EncryptorDecryptor.h"
#include "../TcpReassembly/TcpReassembly.h"

class ProgramController
{
    int selectedOption_;
    PcapFileReader& pcapFileReader_;
    FileCreator& fileCreator_;
    EncryptorDecryptor& encryptorDecryptor_;
    TcpReassembly& tcpReassembly_;

public:
    ProgramController(
            PcapFileReader& reader, FileCreator& fileCreator,
            EncryptorDecryptor& encryptorDecryptor, TcpReassembly& tcpReassembly);
    static void clearScreen();
    void printApplicationBanner();
    void printMenu();
    void askUserToSelectOption();
    void performSelectedOption();
    void printResult();
    void fakePause(std::string message = "Press any key to continue...");
    int getSelectedOption();

    ~ProgramController();
};


#endif //PCAPANALYST_PROGRAMCONTROLLER_H

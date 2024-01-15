//
// Created by Ilya Aldabaev on 18/10/2023.
//

#include <iostream>
#include <cstdlib>

#include "ProgramController.h"

#include "../ComputeSHA256/ComputeSHA256.h"

ProgramController::ProgramController(
        PcapFileReader& reader,
        FileCreator& fileCreator,
        EncryptorDecryptor& encryptorDecryptor,
        TcpReassembly& tcpReassembly)
    : selectedOption_(1),
      pcapFileReader_(reader),
      fileCreator_(fileCreator),
      encryptorDecryptor_(encryptorDecryptor),
      tcpReassembly_(tcpReassembly)
{
    pcapFileReader_.readFile();
}

void ProgramController::clearScreen()
{
#ifdef WINDOWS
    std::system("cls");
#else
    std::system ("clear");
#endif
}

void ProgramController::printMenu()
{
    std::cout << "\n======Options======\n" << std::endl;

    std::cout << "0. Exit" << std::endl;
    std::cout << "1. Print number of packets" << std::endl;
    std::cout << "2. Print all source and destination IPv4 address" << std::endl;
    std::cout << "3. Print source and destination IPv4 address of selected packet" << std::endl;
    std::cout << "4. Print additional packet info of selected packet" << std::endl;
    std::cout << "5. Print list of most frequent IPv4 addresses in Pcap" << std::endl;
    std::cout << "6. Print packets with suspicious data" << std::endl;
    std::cout << "7. Get PNG or PDF from file" << std::endl;
    std::cout << "8. Find emails in pcap file" << std::endl;
    std::cout << "9. Decrypt data from txt file" << std::endl;

}

void ProgramController::askUserToSelectOption()
{
    std::cout << "Select option: ";
    std::cin >> selectedOption_;
}

int ProgramController::getSelectedOption()
{
    return selectedOption_;
}

void ProgramController::performSelectedOption()
{
    std::cout << std::endl;
    bool isPngPdfOption = false;

    switch (selectedOption_)
    {
        case 0:
            std::cout << "Exiting..." << std::endl;
            return;
        case 1:
            pcapFileReader_.addNumberOfPacketsToOutput();
            break;
        case 2:
            pcapFileReader_.addAllSrcAndDstIpv4AddressToOutput();
            break;
        case 3:
            int packetNumber;
            std::cout << "Enter packet number: ";
            std::cin >> packetNumber;
            pcapFileReader_.addSrcAndDstIpv4AddressToOutput(packetNumber);
            break;
        case 4:
            int packetNumber2;
            std::cout << "Enter packet number: ";
            std::cin >> packetNumber2;
            pcapFileReader_.addAdditionalPacketInfoToOutput(packetNumber2);
            break;
        case 5:
            std::cout << "=====================" << std::endl;
            pcapFileReader_.addNumberOfIpv4OccurrencesToOutput();
            break;
        case 6:
            std::cout << "=====================" << std::endl;
            pcapFileReader_.addPacketsWithSuspiciousDataToOutput();
            break;
        case 7:
            TcpReassembly::findAndExtractFiles(pcapFileReader_.getFileName(), "./Output/output"); // uncomment to extract png file from pcap file
            isPngPdfOption = true;
            break;
        case 8:
            pcapFileReader_.addStringToOutput(
                    TcpReassembly::getEmailsInPcapFile(pcapFileReader_.getFileName()));
            break;
        case 9:
            encryptorDecryptor_.setEncryptedText(fileCreator_.readFromFile("./Output/encrypted.txt"));
            encryptorDecryptor_.decryptString();
            encryptorDecryptor_.printDecryptedText();
            break;
        default:
            std::cout << "Invalid option!" << std::endl;
            break;
    }
    printResult();

    std::cout << "\nThat's all for today? :D\n\n";
    std::cout << "0. Exit" << std::endl;
    std::cout << "1. Back to options" << std::endl;
    if (not isPngPdfOption)
    {
        std::cout << "2. Wrote data to txt file" << std::endl;
        std::cout << "3. Encrypt data and wrote to txt file\n" << std::endl;
    }
    askUserToSelectOption();
    if (selectedOption_ == 2)
    {
        fileCreator_.clearFile();
        fileCreator_.writeToFile(pcapFileReader_.getOutputStr());
        ComputeSHA256::computeAndPrintSHA256("output.txt");
        fakePause(std::string{"\nPlease save above sha256 or it will be lost! Press Y to continue: "});
    }
    if (selectedOption_ == 3)
    {
        encryptorDecryptor_.encrypString(pcapFileReader_.getOutputStr());
        fileCreator_.clearFile("./Output/encrypted.txt");
        fileCreator_.writeToFile(encryptorDecryptor_.getEncryptedText(), "./Output/encrypted.txt");

        ComputeSHA256::computeAndPrintSHA256("./Output/encrypted.txt");

        fakePause(std::string{"\nPlease save above key or it will be lost! Press Y to continue: "});
    }

    pcapFileReader_.clearOutputStringStream();
}

void ProgramController::printApplicationBanner()
{
    std::cout << "\n"
                 " ____    ____     ______  ____        ______  __  __  ______  __       __    __  ____    ______   \n"
                 "/\\  _`\\ /\\  _`\\  /\\  _  \\/\\  _`\\     /\\  _  \\/\\ \\/\\ \\/\\  _  \\/\\ \\     /\\ \\  /\\ \\/\\  _`\\ /\\__  _\\  \n"
                 "\\ \\ \\L\\ \\ \\ \\/\\_\\\\ \\ \\L\\ \\ \\ \\L\\ \\   \\ \\ \\L\\ \\ \\ `\\\\ \\ \\ \\L\\ \\ \\ \\    \\ `\\`\\\\/'/\\ \\,\\L\\_\\/_/\\ \\/  \n"
                 " \\ \\ ,__/\\ \\ \\/_/_\\ \\  __ \\ \\ ,__/    \\ \\  __ \\ \\ , ` \\ \\  __ \\ \\ \\  __`\\ `\\ /'  \\/_\\__ \\  \\ \\ \\  \n"
                 "  \\ \\ \\/  \\ \\ \\L\\ \\\\ \\ \\/\\ \\ \\ \\/      \\ \\ \\/\\ \\ \\ \\`\\ \\ \\ \\/\\ \\ \\ \\L\\ \\ `\\ \\ \\    /\\ \\L\\ \\ \\ \\ \\ \n"
                 "   \\ \\_\\   \\ \\____/ \\ \\_\\ \\_\\ \\_\\       \\ \\_\\ \\_\\ \\_\\ \\_\\ \\_\\ \\_\\ \\____/   \\ \\_\\   \\ `\\____\\ \\ \\_\\\n"
                 "    \\/_/    \\/___/   \\/_/\\/_/\\/_/        \\/_/\\/_/\\/_/\\/_/\\/_/\\/_/\\/___/     \\/_/    \\/_____/  \\/_/\n"
                 "                                                                                                  \n"
                 "                                                                                                  ";
}

void ProgramController::printResult()
{
    std::cout << pcapFileReader_.getOutputStr() << std::endl;
}

void ProgramController::fakePause(std::string message)
{
    char temp;
    std::cout << message;
    std::cin >> temp;
}

ProgramController::~ProgramController()
{}

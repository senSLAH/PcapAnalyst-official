#include <Packet.h>

#include "PcapFileReader/PcapFileReader.h"
#include "ProgramController/ProgramController.h"
#include "FileCreator/FileCreator.h"
#include "EncryptorDecryptor/EncryptorDecryptor.h"
#include "ComputeSHA256/ComputeSHA256.h"
#include "TcpReassembly/TcpReassembly.h"


int main(int argc, char* argv[])
{
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " -s path_to_file" << std::endl;
        return 1; // Return an error code
    }

    std::string option = argv[1];
    std::string filePath = argv[2];

    if (option != "-s")
    {
        std::cerr << "Invalid option. Usage: " << argv[0] << " -s path_to_file" << std::endl;
        return 1; // Return an error code
    }

    auto fileName = std::string(filePath);
    auto outputFileName = std::string("output");
    PcapFileReader reader(fileName);
    FileCreator fileCreator;
    EncryptorDecryptor encryptorDecryptor;
    TcpReassembly tcpReassembly;
    ProgramController controller(reader, fileCreator, encryptorDecryptor, tcpReassembly);

    while (controller.getSelectedOption() != 0)
    {
        controller.clearScreen();
        controller.printApplicationBanner();
        controller.printMenu();
        controller.askUserToSelectOption();
        controller.performSelectedOption();
    }

    return 0;
}

cmake_minimum_required(VERSION 3.12)

project(PcapAnalyst)

set(CMAKE_CXX_STANDARD 17)
add_executable("${PROJECT_NAME}" main.cpp
        PcapFileReader/PcapFileReader.cpp
        PcapFileReader/PcapFileReader.h
        ProgramController/ProgramController.cpp
        ProgramController/ProgramController.h
        FileCreator/FileCreator.cpp
        FileCreator/FileCreator.h
        EncryptorDecryptor/EncryptorDecryptor.cpp
        EncryptorDecryptor/EncryptorDecryptor.h
        ComputeSHA256/ComputeSHA256.cpp
        ComputeSHA256/ComputeSHA256.h
        TcpReassembly/TcpReassembly.cpp
        TcpReassembly/TcpReassembly.h
)

find_package(PcapPlusPlus REQUIRED)
find_package(OpenSSL REQUIRED)

set_target_properties("${PROJECT_NAME}" PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries("${PROJECT_NAME}" PUBLIC PcapPlusPlus::Pcap++)
target_link_libraries("${PROJECT_NAME}" PUBLIC OpenSSL::SSL OpenSSL::Crypto)

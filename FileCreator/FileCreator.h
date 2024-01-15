//
// Created by Illia Aldabaiev on 19/10/2023.
//

#ifndef PCAPANALYST_FILECREATOR_H
#define PCAPANALYST_FILECREATOR_H

#include <iostream>
#include <fstream>
#include <string>

class FileCreator {
    std::string fileName_;

public:
    FileCreator();
    void writeToFile(const std::string& data, const std::string fileName = "output.txt" );
    std::string readFromFile(const std::string fileName = "output.txt");
    void clearFile(const std::string fileName = "output.txt");
    std::string getFileName();
};


#endif //PCAPANALYST_FILECREATOR_H

//
// Created by Illia Aldabaiev on 19/10/2023.
//

#include "FileCreator.h"

FileCreator::FileCreator()
{}

//create function to open and write to file
void FileCreator::writeToFile(const std::string& data, const std::string fileName)
{
    std::ofstream file;
    file.open(fileName, std::ios::app);
    file << data << std::endl;
    file.close();
}

//create function to clear file
void FileCreator::clearFile(const std::string fileName)
{
    std::ofstream file;
    file.open(fileName, std::ios::trunc);
    file.close();
}

std::string FileCreator::getFileName()
{
    return fileName_;
}

std::string FileCreator::readFromFile(const std::string fileName)
{
    std::ifstream file;
    std::string line;
    std::string fileContent;
    file.open(fileName);
    if (file.is_open())
    {
        while (getline(file, line))
        {
            fileContent += line + "\n";
        }
        file.close();
    }
    else
    {
        std::cout << "Unable to open file";
    }
    return fileContent;
}


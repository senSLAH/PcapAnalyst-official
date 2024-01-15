//
// Created by Illia Aldabaiev on 25/10/2023.
//

#include "TcpReassembly.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <cstdint>
#include <map>
#include <TcpReassembly.h>

#include "PcapFileDevice.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "HttpLayer.h"
#include "Packet.h"

#include "PcapLiveDeviceList.h"
#include "TcpReassembly.h"


#define PNG_SIGNATURE "89504e470d0a1a0a"
#define PDF_SIGNATURE "25504446"
#define PDF_END_SIGNATURE "2525454F46"




TcpReassembly::TcpReassembly()
{}

void TcpReassembly::findAndExtractFiles(const std::string& fileName, const std::string& outputFileName)
{
    auto allDataStr = getAllDataFromSelectedStream(fileName);

    if (isHexContainsPngSignature(allDataStr))
    {
        auto index = allDataStr.find(PNG_SIGNATURE);
        allDataStr = allDataStr.substr(index, allDataStr.length());
        std::cout << allDataStr << std::endl;
        std::cout << "PNG signature found!" << std::endl;
        basedOnHexCreateImgFile(allDataStr, outputFileName + ".png");
    }
    else if (isHexContainsPdfSignature(allDataStr))
    {
        auto index = allDataStr.find(PDF_SIGNATURE);
        allDataStr = allDataStr.substr(index, allDataStr.length());
        std::cout << allDataStr << std::endl;
        std::cout << "PDF signature found!" << std::endl;
        basedOnHexCreateImgFile(allDataStr, outputFileName + ".pdf");
    }
    else
    {
        std::cout << "PNG and PDF signature not found!" << std::endl;
    }
}

std::string TcpReassembly::getAllDataFromSelectedStream(const std::string &fileName)
{
    auto indificatorAndStringMap = getAllDataInHexFromPcapFile(fileName);
    auto allDataStr = indificatorAndStringMap.begin()->second;
    auto secondValueIt = indificatorAndStringMap.begin();

    if (indificatorAndStringMap.size() > 1)
    {
        auto streamId = 0;
        //find wich tread contain pdf/png signature
        streamId = getStreamIndexWhichContainsSignature(indificatorAndStringMap); // asking user which tcp stream to choose
        std::advance(secondValueIt, streamId);
        allDataStr = secondValueIt->second;
    }

    return allDataStr;
}

std::map<StreamIndificator, std::string> TcpReassembly::getAllDataInHexFromPcapFile(const std::string &fileName)
{
    auto reader = pcpp::IFileReaderDevice::getReader(fileName);

    if (!reader->open()) std::cout << "Cannot open pcap/pcapng file" << std::endl;

    auto outputIndificatorAndStringMap = std::map<StreamIndificator, std::string>();
    auto rawPacket = pcpp::RawPacket{};

    while (reader->getNextPacket(rawPacket))
    {
        auto outputStringStream = std::ostringstream{};
        auto parsedPacket = pcpp::Packet{&rawPacket};
        auto headerSize = 0;
        auto ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        auto tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();

        if (ipv4Layer == nullptr || !parsedPacket.isPacketOfType(pcpp::TCP))
        {
            continue;
        }

        StreamIndificator streamIndificator{
                ipv4Layer->getSrcIPv4Address(),
                ipv4Layer->getDstIPv4Address(),
                tcpLayer->getSrcPort(),
                tcpLayer->getDstPort()
        };

        headerSize = getLayerHeaderSize(parsedPacket);
        outputStringStream << getHexDataFromPacketWithoutHeaderInStr(rawPacket, headerSize);

        if (outputIndificatorAndStringMap.find(streamIndificator) == outputIndificatorAndStringMap.end())
        {
            outputIndificatorAndStringMap.insert(std::pair<StreamIndificator, std::string>(streamIndificator, outputStringStream.str()));
        }
        else
        {
            outputIndificatorAndStringMap[streamIndificator] += outputStringStream.str();
        }
    }

    reader->close();
    delete reader;

    return  outputIndificatorAndStringMap;
}

std::string TcpReassembly::getAllHttpLayerDataFromPcapFile(const std::string &fileName)
{
    auto reader = pcpp::IFileReaderDevice::getReader(fileName);

    if (!reader->open()) std::cout << "Cannot open pcap/pcapng file" << std::endl;

    auto rawPacket = pcpp::RawPacket{};
    auto outputStringStream = std::ostringstream{};

    while (reader->getNextPacket(rawPacket))
    {
        auto parsedPacket = pcpp::Packet{&rawPacket};
        auto ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        auto httpLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();

        if (ipv4Layer == nullptr || httpLayer == nullptr || !parsedPacket.isPacketOfType(pcpp::TCP))
        {
            continue;
        }

        auto httpData = httpLayer->getLayerPayload();
        auto httpDataSize = httpLayer->getLayerPayloadSize();

        outputStringStream
            << std::string(httpData, httpData+httpDataSize) << " ";
    }
    return outputStringStream.str();
}

int TcpReassembly::askUserToSelectStream(const std::map<StreamIndificator, std::string> &indificatorAndStringMap)
{
    auto streamId = 0;
    std::cout << "There are " << indificatorAndStringMap.size() << " streams available:\n" << std::endl;

    for (auto const& element : indificatorAndStringMap)
    {
        std::cout << "StreamId: " << streamId << " Key: " << element.first.srcIP << " " << element.first.srcPort
            << " -> " << element.first.destIP << " " << element.first.destPort << std::endl;
        streamId++;
    }

    std::cout << "Please select one stream, provide stream id: " << std::endl;
    std::cin >> streamId;
    return streamId;
}

int TcpReassembly::getStreamIndexWhichContainsSignature(
        const std::map<StreamIndificator, std::string> &indificatorAndStringMap)
{
    auto streamId = 0;

    for (auto const& element : indificatorAndStringMap)
    {
        if (element.second.find(PNG_SIGNATURE) != std::string::npos ||
            element.second.find(PDF_SIGNATURE) != std::string::npos)
        {
            return streamId;
        }
        streamId++;
    }

    return streamId;
}

std::string TcpReassembly::getHexDataFromPacketWithoutHeaderInStr(const pcpp::RawPacket &rawPacket, const int &headerSize)
{
    std::ostringstream outputStringStreamFromPacket;
    for (auto j = headerSize; j < rawPacket.getRawDataLen(); j++)
    {
        auto data = (int)rawPacket.getRawData()[j];
        auto ssToCheckLength = std::ostringstream{};

        ssToCheckLength << std::hex << data;

        if (ssToCheckLength.str().length() == 1)
        {
            outputStringStreamFromPacket << "0" << ssToCheckLength.str();
        }
        else
        {
            outputStringStreamFromPacket << ssToCheckLength.str();
        }
    }
    return outputStringStreamFromPacket.str();
}

int TcpReassembly::getLayerHeaderSize(const pcpp::Packet &packet)
{
    int headerSize = 0;
    for (auto currentLayer = packet.getFirstLayer(); currentLayer != nullptr; currentLayer = currentLayer->getNextLayer())
    {
        auto layerType = currentLayer->getProtocol();
        auto layerHeaderSize = (int)currentLayer->getHeaderLen();

        if (getProtocolTypeAsString(layerType) != "Unknown")
        {
            headerSize += layerHeaderSize;
        }
    }

    return headerSize;
}

std::string TcpReassembly::getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
        case pcpp::Ethernet:
            return "Ethernet";
        case pcpp::IPv4:
            return "IPv4";
        case pcpp::TCP:
            return "TCP";
        case pcpp::HTTPRequest:
        case pcpp::HTTPResponse:
            return "HTTP";
        default:
            return "Unknown";
    }
}

bool TcpReassembly::isHexContainsPngSignature(const std::string &hexString) 
{
    return hexString.find(PNG_SIGNATURE) != std::string::npos;
}

bool TcpReassembly::isHexContainsPdfSignature(const std::string &hexString)
{
    return hexString.find(PDF_SIGNATURE) != std::string::npos;
}

void TcpReassembly::basedOnHexCreateImgFile(const std::string& hexStr, const std::string& outputFileName)
{
    auto asciiData = hexToASCII(hexStr);
    auto pngFile = std::ofstream {outputFileName, std::ios::out | std::ios::binary}; // write ascii data to png file
    pngFile << asciiData;
    pngFile.close();
    std::cout << outputFileName << " created!" << std::endl;
}

std::string TcpReassembly::hexToASCII(const std::string hexString)
{
    auto ascii = std::string{};
    for (size_t i = 0; i < hexString.length(); i += 2)
    {
        auto part = hexString.substr(i, 2);
        auto ch = std::stoul(part, nullptr, 16); // change it into base 16 and typecast as the character

        ascii += ch;
    }
    return ascii;
}

std::string TcpReassembly::getEmailsInPcapFile(const std::string &fileName)
{
    const std::regex pattern(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)");
    auto httpLayerDataStr = getAllHttpLayerDataFromPcapFile(fileName);
    auto index = httpLayerDataStr.find("%40");
    auto emails = std::stringstream{};

    while (index != std::string::npos) {
        httpLayerDataStr.replace(index, 3, "@");
        index = httpLayerDataStr.find("%40");
    }

    auto words_begin = std::sregex_iterator(httpLayerDataStr.begin(), httpLayerDataStr.end(), pattern);
    auto words_end = std::sregex_iterator();

    if (std::distance(words_begin, words_end) == 0)
    {
        emails << "No emails found!" << std::endl;
        return emails.str();
    }

    emails << "Extracted emails:" << std::endl;

    for (std::sregex_iterator i = words_begin; i != words_end; ++i)
    {
        emails << (i->str()) << std::endl;
    }

    return emails.str();
}

std::string TcpReassembly::getHttpMethodType(const pcpp::HttpRequestLayer* httpLayerOfPacket)
{
    auto httpMethod = httpLayerOfPacket->getFirstLine()->getMethod();
    auto httpUrl = httpLayerOfPacket->getFirstLine()->getUri();
    //auto httpVersion = httpLayerOfPacket->getFirstLine()->getVersion(); //currently not used

    if (httpMethod == pcpp::HttpRequestLayer::HttpGET)
    {
        return "HTTP GET request: " + httpUrl;
    }
    else if (httpMethod == pcpp::HttpRequestLayer::HttpPOST)
    {
        return "HTTP POST request: " + httpUrl;
    }
    else if (httpMethod == pcpp::HttpRequestLayer::HttpPUT)
    {
        return "HTTP PUT request: " + httpUrl;
    }
    else if (httpMethod == pcpp::HttpRequestLayer::HttpDELETE)
    {
        return "HTTP DELETE request: " + httpUrl;
    }
    else if (httpMethod == pcpp::HttpRequestLayer::HttpHEAD)
    {
        return "HTTP HEAD request: " + httpUrl;
    }
    else if (httpMethod == pcpp::HttpRequestLayer::HttpOPTIONS)
    {
        return "HTTP OPTIONS request: " + httpUrl;
    }
    else if (httpMethod == pcpp::HttpRequestLayer::HttpTRACE)
    {
        return "HTTP TRACE request: " + httpUrl;
    }
    else if (httpMethod == pcpp::HttpRequestLayer::HttpCONNECT)
    {
        return "HTTP CONNECT request: " + httpUrl;
    }
    else if (httpMethod == pcpp::HttpRequestLayer::HttpPATCH)
    {
        return "HTTP PATCH request: " + httpUrl;
    }
    else
    {
        return "HTTP request: " + httpUrl;
    }
}




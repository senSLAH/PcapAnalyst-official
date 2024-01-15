//
// Created by Illia Aldabaiev on 25/10/2023.
//

#ifndef PCAPANALYST_TCPREASSEMBLY_H
#define PCAPANALYST_TCPREASSEMBLY_H

#include <string>
#include <map>

#include <ProtocolType.h>
#include <Packet.h>
#include <IpAddress.h>
#include "HttpLayer.h"

struct StreamIndificator //hack because there is no option to get Stream index
{
    pcpp::IPv4Address srcIP;
    pcpp::IPv4Address destIP;
    uint16_t srcPort;
    uint16_t destPort;

    bool operator<(const StreamIndificator& other) const {
        return (srcIP.toInt() < other.srcIP.toInt()) ||
               (srcIP.toInt() == other.srcIP.toInt() && destIP.toInt() < other.destIP.toInt()) ||
               (srcIP.toInt() == other.srcIP.toInt() && destIP.toInt() == other.destIP.toInt() && srcPort < other.srcPort) ||
               (srcIP.toInt() == other.srcIP.toInt() && destIP.toInt() == other.destIP.toInt() && srcPort == other.srcPort && destPort < other.destPort);
    }

};

class TcpReassembly
{

public:
    TcpReassembly();
    static void findAndExtractFiles(const std::string& fileName, const std::string& outputFileName);
    static std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType);
    static std::map<StreamIndificator, std::string> getAllDataInHexFromPcapFile(const std::string& fileName);
    static std::string getAllHttpLayerDataFromPcapFile(const std::string& fileName);
    static std::string getAllDataFromSelectedStream(const std::string& fileName);
    static bool isHexContainsPngSignature(const std::string& hexString);
    static bool isHexContainsPdfSignature(const std::string& hexString);
    static int getLayerHeaderSize(const pcpp::Packet& packet);
    static int askUserToSelectStream(const std::map<StreamIndificator, std::string>& indificatorAndStringMap);
    static int getStreamIndexWhichContainsSignature(const std::map<StreamIndificator, std::string>& indificatorAndStringMap); // return first index in which signature was found
    static std::string getHexDataFromPacketWithoutHeaderInStr(const pcpp::RawPacket &rawPacket, const int &headerSize);
    static void basedOnHexCreateImgFile(const std::string& hexStr, const std::string& outputFileName = "output.png");
    static std::string hexToASCII(const std::string hexString);
    static std::string getHttpMethodType(const pcpp::HttpRequestLayer* httpLayerOfPacket);

    static std::string getEmailsInPcapFile(const std::string& fileName);

};


#endif //PCAPANALYST_TCPREASSEMBLY_H

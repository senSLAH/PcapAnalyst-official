//
// Created by Ilya Aldabaev on 18/10/2023.
//

#ifndef PCAPANALYST_PCAPFILEREADER_H
#define PCAPANALYST_PCAPFILEREADER_H

#include <sstream>

#include <PcapFileDevice.h>
#include <HttpLayer.h>


class PcapFileReader
{
    std::string fileName_;
    pcpp::PcapFileReaderDevice reader_;
    std::vector<pcpp::Packet> packets_;
    std::ostringstream outputStringStream_;

public:
    PcapFileReader(std::string& fileName);
    void readFile();

    void addNumberOfPacketsToOutput();
    void addSrcAndDstIpv4AddressToOutput(int packetNumber = 0);
    void addAllSrcAndDstIpv4AddressToOutput();
    void addAdditionalPacketInfoToOutput(int packetNumber = 0);
    void addNumberOfIpv4OccurrencesToOutput();
    void addPacketsWithSuspiciousDataToOutput();
    void addStringToOutput(std::string string);
    std::string getFileName() const;

    bool isSuspiciousData(const pcpp::Packet& packet);
    std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod);


    void clearOutputStringStream();
    std::string getOutputStr();
    std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType);

    ~PcapFileReader();
};


#endif //PCAPANALYST_PCAPFILEREADER_H

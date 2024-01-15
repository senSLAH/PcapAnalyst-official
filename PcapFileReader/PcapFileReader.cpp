//
// Created by Ilya Aldabaev on 18/10/2023.
//

#include <iostream>
#include <cstdlib>
#include <algorithm>
#include <map>

#include "PcapFileReader.h"

#include <IPv4Layer.h>
#include <TcpLayer.h>
#include <HttpLayer.h>
#include <Packet.h>

PcapFileReader::PcapFileReader(std::string& fileName)
    : fileName_(fileName),
        reader_(fileName)
{
    // open a pcap file for reading
    if (!reader_.open())
    {
        std::cerr << "Error opening the pcap file" << std::endl;
        exit(1);
    }
}

void PcapFileReader::readFile()
{
    pcpp::RawPacket rawPacket;
    while (reader_.getNextPacket(rawPacket))
    {
        packets_.push_back(pcpp::Packet(&rawPacket));
    }
}

void PcapFileReader::addNumberOfPacketsToOutput()
{
    outputStringStream_ << "Total packets read: " << packets_.size() << std::endl;
}

void PcapFileReader::addSrcAndDstIpv4AddressToOutput(int packetNumber)
{
    auto parsedPacket = packets_.at(packetNumber);

    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // extract source and dest IPs
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

        // print source and dest IPs
        outputStringStream_
                << "Packet #" << packetNumber << ": "
                << "Source IP is '" << srcIP << "'; "
                << "Dest IP is '" << destIP << "'"
                << std::endl;
    }
}

void PcapFileReader::addAllSrcAndDstIpv4AddressToOutput()
{
    for (int i = 0; i < packets_.size(); ++i)
    {
        addSrcAndDstIpv4AddressToOutput(i);
    }
}

std::string PcapFileReader::getProtocolTypeAsString(pcpp::ProtocolType protocolType)
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

void PcapFileReader::addAdditionalPacketInfoToOutput(int packetNumber)
{
    auto parsedPacket = packets_.at(packetNumber);

    outputStringStream_ << "Start of Packet #" << packetNumber << " ================" <<std::endl;
    for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
        {
            outputStringStream_
                    << "Layer type: " << getProtocolTypeAsString(curLayer->getProtocol()) << "; " // get layer type
                    << "Total data: " << curLayer->getDataLen() << " [bytes]; " // get total length of the layer
                    << "Layer data: " << curLayer->getHeaderLen() << " [bytes]; " // get the header length of the layer
                    << "Layer payload: " << curLayer->getLayerPayloadSize() << " [bytes]" // get the payload length of the layer (equals total length minus header length)
                    << std::endl;
        }
    outputStringStream_ << "End of Packet #" << packetNumber << " ==================" << std::endl << std::endl;
}

std::string PcapFileReader::getOutputStr()
{
    return outputStringStream_.str();
}

PcapFileReader::~PcapFileReader()
{
    std::cout << "File \"" << fileName_ << "\" closed!" << std::endl;
    reader_.close();
}

void PcapFileReader::clearOutputStringStream()
{
    outputStringStream_.str("");
}

void PcapFileReader::addNumberOfIpv4OccurrencesToOutput()
{
    std::map<pcpp::IPv4Address, int> ipMap;
    for (const auto& parsedPacket : packets_)
    {
        if (parsedPacket.isPacketOfType(pcpp::IPv4))
        {
            pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
            pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

            ipMap[srcIP]++;
            ipMap[destIP]++;
        }
    }

    std::vector<std::pair<pcpp::IPv4Address, int>> ipVector;
    ipVector.reserve(ipMap.size());
    for (const auto& it : ipMap)
    {
        ipVector.emplace_back(it);
    }

    std::sort(ipVector.begin(), ipVector.end(), [](
            const auto& a, const auto& b) {
        return a.second > b.second;
    });

    for (const auto& it : ipVector)
    {
        outputStringStream_ << it.first << " - " << it.second << std::endl;
    }
}

void PcapFileReader::addPacketsWithSuspiciousDataToOutput()
{
    int packetNumber = 0;
    for (const auto& parsedPacket : packets_)
    {
        if (isSuspiciousData(parsedPacket))
        {
            outputStringStream_ << "=======Suspicious data found in packet #" << packetNumber << "=======\n"<< std::endl;
        }
        ++packetNumber;
    }
}

bool PcapFileReader::isSuspiciousData(const pcpp::Packet &packet)
{

    const auto httpRequestLayer = packet.getLayerOfType<pcpp::HttpRequestLayer>();

    if (httpRequestLayer == NULL)
    {
        return false;
    }

    outputStringStream_ << std::endl
              << "HTTP method: " << printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()) << std::endl
              << "HTTP URI: " << httpRequestLayer->getFirstLine()->getUri() << std::endl;

    return true;
}

std::string PcapFileReader::printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
{
    switch (httpMethod)
    {
        case pcpp::HttpRequestLayer::HttpGET:
            return "GET";
        case pcpp::HttpRequestLayer::HttpPOST:
            return "POST";
        default:
            return "Other";
    }
}

std::string PcapFileReader::getFileName() const
{
    return fileName_;
}

void PcapFileReader::addStringToOutput(std::string string)
{
    outputStringStream_ << string << std::endl;
}







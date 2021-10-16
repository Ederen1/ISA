//
// Created by vitek on 10/2/2021.
//

#ifndef ISAA_SENDER_H
#define ISAA_SENDER_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/icmp.h>
#include <array>
#include <vector>
#include "Encryption.h"
#include "icmp.h"

using namespace std;

class Sender {
public:
    Sender(in_addr addr) {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock == -1) {
            throw "Unable to open socket";
        }

        _socket = sock;
        _address.sin_addr = addr;
    }

    ~Sender() {
        close(_socket);
    }

    void SendFile(const string &filePath) {
        vector<char> fileContent = GetFileContents(filePath);
        auto encrypted = Encryption::Encrypt(fileContent);

        auto[head, info] = MakeInfoPacket(filePath, encrypted);
        SendPacket(head, info);

        size_t chunkSize = ((1500 - sizeof(head) - 34) / 16 + 1) * 16;
        for (int i = 0; i <= encrypted.size() / chunkSize; i++) {
            ICMP_head head{8, 0, 0, static_cast<uint16_t>(getpid()), static_cast<uint16_t>(i)};

            auto toSendDataSize = chunkSize;
            if(chunkSize * (i + 1) > encrypted.size())
                toSendDataSize = encrypted.size() % chunkSize;

            const auto &packetStart = encrypted.begin() + chunkSize * i;
            auto toSend = vector(packetStart, packetStart + toSendDataSize);
            SendPacket(head, toSend);
        }
    }

private:
    sockaddr_in _address{.sin_family = AF_INET};
    int _socket{};

    void SendPacket(ICMP_head head, PROTO_info info) const {
        auto packetBuffer = BuildICMPToBuffer(head, info);
        head.checksum = checksum(packetBuffer.data(), packetBuffer.size());

        SendToSocket(packetBuffer);
    }

    void SendPacket(ICMP_head head, vector<char> data) const {
        auto packetBuffer = BuildICMPToBuffer(head, data);
        head.checksum = checksum(packetBuffer.data(), packetBuffer.size());

        SendToSocket(packetBuffer);
    }

    void SendToSocket(vector<char> &packetBuffer) const {
        sendto(_socket, static_cast<const void *>(packetBuffer.data()), packetBuffer.size(), 0,
               reinterpret_cast<const sockaddr *>(&_address),
               sizeof(_address));
    }


    pair<ICMP_head, PROTO_info> MakeInfoPacket(const string &filePath, const vector<char> &encrypted) const {
        ICMP_head head{
                .type = 8,
                .identifier = static_cast<uint16_t>(getpid()),
        };

        PROTO_info info;
        info.sentFileSize = encrypted.size();

        string fileName = filePath.substr(filePath.find_last_of("/\\") + 1);
        memcpy(&info.fileName, fileName.data(), fileName.size());

        return make_pair(head, info);
    }

    uint32_t checksum(const char *addr, size_t count) const {
        uint32_t sum = 0;

        uint16_t *addrCpy = (uint16_t *) addr;
        // Main summing loop
        while (count > 1) {
            sum = sum + *(addrCpy++);
            count = count - 2;
        }

        // Add left-over byte, if any
        if (count > 0)
            sum = sum + *((char *) addrCpy);

        // Fold 32-bit sum to 16 bits
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
    }

    vector<char> GetFileContents(const string &filePath) const {
        if (filePath.empty())
            throw "File path not specified";

        ifstream fileToEncrypt(filePath, ios::in | ios::binary);
        if (fileToEncrypt.fail())
            throw "File cannot be opened";

        stringstream ss;
        ss << fileToEncrypt.rdbuf();
        auto content = ss.str();

        return vector(content.begin(), content.end());
    }
};


#endif //ISAA_SENDER_H

//
// Created by vitek on 10/6/2021.
//

#ifndef ISAA_RECEIVER_H
#define ISAA_RECEIVER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


class Receiver {
public:
    Receiver() {
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock == -1) {
            throw "Unable to open socket";
        }

        _socket = sock;
    }

    ~Receiver() {
        close(_socket);
    }

    void Receive() {
        BindSocket();

        while (1) {
            PROTO_info info = GetPROTOInfo();
            RecieveFileData(info);
        }
    }

private:
    int _socket{};

    void RecieveFileData(const PROTO_info &info) {
        int bytesRead = 0;
        ofstream out(info.fileName, ios::out | ios::binary);
        while (1) {
            auto data = RecieveICMPPacket();
            auto[_, body] = BufferToIcmpBody(data);
            auto decrypted = Encryption::Decrypt(body);

            bytesRead += body.size();
            out.write(decrypted.data(), decrypted.size());

            if (bytesRead == info.sentFileSize)
                break;
            if (bytesRead > info.sentFileSize)
                throw "Recieved too much data on socket";
        }
    }

    void BindSocket() const {
        sockaddr_in si_me{};

        si_me.sin_family = AF_INET;
        si_me.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(_socket, reinterpret_cast<const sockaddr *>(&si_me), sizeof(si_me)) == -1) {
            throw "Binding error";
        }
    }

    PROTO_info GetPROTOInfo() {
        auto buffer = RecieveICMPPacket();
        auto[_, info] = BufferToIcmpInfo(buffer);

        return info;
    }

    vector<char> RecieveICMPPacket() {
        static const int BUFLEN = 2048;
        static char buf[BUFLEN];

        vector<char> ret;
        int recvLen = 0;
        int recvAll = 0;
        while (1) {
            if ((recvLen = recvfrom(_socket, buf, BUFLEN, 0, nullptr, 0)) == -1)
                throw "recvfrom";

            recvAll += recvLen;
            if (recvAll < 20)
                throw "Invalid packet on socket";

            uint16_t totalLen = ((unsigned char)buf[2] << 8) | (unsigned char)buf[3];
            if (totalLen < 20)
                throw "Corrupted packet on socket";

            for (int i = 0; i < recvLen; i++) {
                ret.insert(ret.end(), buf[i]);
            }

            if (recvAll == totalLen)
                break;
            if (recvAll > totalLen)
                throw "Socket recieved too much data";
        }

        return ret;
    }
};


#endif //ISAA_RECEIVER_H

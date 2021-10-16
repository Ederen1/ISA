//
// Created by vitek on 10/6/2021.
//

#ifndef ISAA_ICMP_H
#define ISAA_ICMP_H

static const int IP_HEADER_SIZE = 20;

#include <tuple>

struct ICMP_head {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequenceNbr;
};

struct PROTO_info {
    size_t sentFileSize{};
    char fileName[255];
};

vector<char> BuildICMPToBuffer(ICMP_head head, PROTO_info info){
    vector<char> buffer(sizeof(head) + sizeof(info));
    memcpy(buffer.data(), &head, sizeof(head));
    memcpy(buffer.data() + sizeof(head), &info, sizeof(info));

    return buffer;
}

vector<char> BuildICMPToBuffer(ICMP_head head, vector<char> data){
    vector<char> buffer(sizeof(head) + data.size());

    memcpy(buffer.data(), &head, sizeof(head));
    for(int i = 0; i < data.size(); i++){
        buffer[sizeof(head) + i] = data[i];
    }

    return buffer;
}

tuple<ICMP_head, PROTO_info> BufferToIcmpInfo(const vector<char>& buffer){
    ICMP_head head;
    PROTO_info info;

    memcpy(&head, buffer.data() + IP_HEADER_SIZE, sizeof(head));
    memcpy(&info, buffer.data() + IP_HEADER_SIZE + sizeof(head), sizeof(info));

    return make_tuple(head, info);
}

tuple<ICMP_head, vector<char>> BufferToIcmpBody(const vector<char>& buffer){
    ICMP_head head;

    memcpy(&head, buffer.data() + IP_HEADER_SIZE, sizeof(head));
    vector<char> body(buffer.begin() + IP_HEADER_SIZE + sizeof(ICMP_head), buffer.end());

    return make_tuple(head, body);
}


#endif //ISAA_ICMP_H

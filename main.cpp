#include <iostream>
#include <netdb.h>
#include <cstring>
#include "Sender.h"
#include "Receiver.h"

using namespace std;

struct Options {
    bool isServer{};
    string filePath{};
    in_addr targetIP{};
};

in_addr getIp(const string &hostnameOrIp) {
    string_view sv{hostnameOrIp};

    auto indexProt = sv.find("://");
    if (indexProt != string::npos) {
        sv.remove_prefix(indexProt + 3);
    }

    auto index_path = sv.find('/');
    if (index_path != string::npos) {
        sv.remove_suffix(sv.size() - index_path);
    }

    auto hostInfo = gethostbyname(string(sv).c_str());
    if (hostInfo == nullptr)
        throw "Unable to resolve hostname";

    auto addr_list = (in_addr **) hostInfo->h_addr_list;
    if (addr_list[0] == nullptr)
        throw "Unable to resolve hostname";

    return *addr_list[0];
}

Options parseArgs(int argc, char const *argv[]) {
    Options opt;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            opt.filePath = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-s") == 0) {
            opt.targetIP = getIp(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-l") == 0) {
            opt.isServer = true;
        }
    }

    if (!opt.isServer) {
        if (opt.filePath.empty())
            throw "Argument -r not specified";
        if (opt.targetIP.s_addr == 0)
            throw "Argument -s not specified";
    }

    return opt;
}

void MainInternal(int argc, char const *argv[]) {
    Options opts = parseArgs(argc, argv);
    if (opts.isServer) {
        Receiver rec;
        rec.Receive();
    } else {
        Sender sender(opts.targetIP);
        sender.SendFile(opts.filePath);
    }
}

int main(int argc, char const *argv[]) {
    try {
        MainInternal(argc, argv);
    }
    catch (const char* ex){
        cerr << ex << endl;
    }
    catch (const std::runtime_error &re) {
        std::cerr << re.what() << std::endl;
    }
}
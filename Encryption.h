//
// Created by vitek on 10/2/2021.
//

#ifndef ISAA_ENCRYPTION_H
#define ISAA_ENCRYPTION_H

#include <openssl/opensslconf.h>
#include <openssl/aes.h>

using namespace std;

#define KEY "xhorky33"

class Encryption {

public:
    static vector<char> Encrypt(const vector<char> &toEncrypt) {
        AES_KEY enc_key;
        auto buffer = toEncrypt;

        auto bufSize = (toEncrypt.size() / 16 + 1) * 16;
        auto padValue = bufSize - buffer.size();
        buffer.resize(bufSize, padValue);

        AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(KEY), 128, &enc_key);
        for (int i = 0; i < buffer.size() / 16; i++) {
            AES_encrypt(reinterpret_cast<const unsigned char *>(buffer.data() + i * 16),
                        reinterpret_cast<unsigned char *>(buffer.data() + i * 16), &enc_key);
        }

        return buffer;
    }

    static vector<char> Decrypt(const vector<char> &toDecrypt) {
        AES_KEY dec_key;
        vector<char> buffer(toDecrypt.size(), 0);

        AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(KEY), 128, &dec_key);

        for (int i = 0; i < toDecrypt.size() / 16; i++) {
            AES_decrypt(reinterpret_cast<const unsigned char *>(toDecrypt.data() + i * 16),
                        reinterpret_cast<unsigned char *>(buffer.data() + i * 16), &dec_key);
        }

        auto stripBy = buffer.back();
        buffer.resize(buffer.size() - stripBy);

        return buffer;
    }
};


#endif //ISAA_ENCRYPTION_H

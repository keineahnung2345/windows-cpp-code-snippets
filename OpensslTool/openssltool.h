#pragma once
#include <fstream>
#include <string>
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#define KEY_LENGTH  2048             // The length of private key

class OpensslTool {
public:
    static void GenerateRSAKey(std::string & out_pub_key, std::string & out_pri_key, 
        const std::string &PUB_KEY_FILE = "pubkey.pem",
        const std::string &PRI_KEY_FILE = "prikey.pem");
    static std::string ReadPublicKey(const std::string &PUB_KEY_FILE = "pubkey.pem");
    static std::string ReadPrivateKey(const std::string &PRI_KEY_FILE = "prikey.pem");
    static std::string RsaPriEncrypt(const std::string &clear_text, const std::string &pri_key);
    static std::string RsaPubDecrypt(const std::string & cipher_text, const std::string & pub_key);
    static std::string RsaPubEncrypt(const std::string &clear_text, const std::string &pub_key);
    static std::string RsaPriDecrypt(const std::string &cipher_text, const std::string &pri_key);
};

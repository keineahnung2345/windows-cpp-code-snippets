#include <string>
#include <iostream>
#include <windows.h>

#include "openssltool.h"

using namespace std;

int main(int argc, char *argv[])
{
    const std::string PUB_KEY_FILE = "../pubkey.pem";
    const std::string PRI_KEY_FILE = "../prikey.pem";
    const std::string LICENSE_KEY_FILE = "../license.key";

    string src_text = "This will be encrypted.";

    string encrypt_text;

    string pub_key = OpensslTool::ReadPublicKey(PUB_KEY_FILE);
    if (pub_key.empty()) {
        cout << "Please check the existence of " << PUB_KEY_FILE << endl;
    }

    cout << "public key:\n";
    cout << pub_key.c_str();

    //server side: public key & private key
    //encrypt it with private key
    string pri_key = OpensslTool::ReadPrivateKey(PRI_KEY_FILE);
    if (pri_key.empty()) {
        cout << "Please check the existence of " << PRI_KEY_FILE << " and reopen the program" << endl;
    }
    cout << "private key:\n";
    cout << pri_key;
    encrypt_text = OpensslTool::RsaPriEncrypt(src_text, pri_key);
    cout << "encrypt: len=" << encrypt_text.length() << endl;
    cout << encrypt_text << endl;

    std::ofstream license_key_file(LICENSE_KEY_FILE, std::ios::binary | std::ios::out);
    if (!license_key_file.is_open()) {
        cout << LICENSE_KEY_FILE << " open fail:" << endl;
    }
    else {
        license_key_file << encrypt_text;
        license_key_file.close();
    }

    system("pause");

    return 0;
}

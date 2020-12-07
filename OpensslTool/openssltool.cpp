#include "openssltool.h"
#include "openssl/applink.c"

//https://blog.csdn.net/qq_30667875/article/details/105427943
//https://blog.csdn.net/qq_44688854/article/details/109739084

/*
Generate key paris: private key and public key
**/
void OpensslTool::GenerateRSAKey(std::string & out_pub_key, std::string & out_pri_key,
    const std::string &PUB_KEY_FILE, const std::string &PRI_KEY_FILE)
{
    size_t pri_len = 0; // The length of private key
    size_t pub_len = 0; // The length of public key
    char *pri_key = nullptr; // private key
    char *pub_key = nullptr; // public key

                             // Generate private key pairs
    RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    // Generate private key
    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    // Generate public key of first format
    //PEM_write_bio_RSAPublicKey(pub, keypair);
    // Generate public key of second format
    PEM_write_bio_RSA_PUBKEY(pub, keypair);

    // Get lengths
    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    // Read keys into strings 
    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    out_pub_key = pub_key;
    out_pri_key = pri_key;

    // Save public key
    std::ofstream pub_file(PUB_KEY_FILE, std::ios::out);
    if (!pub_file.is_open())
    {
        perror("pub key file open fail:");
        return;
    }
    pub_file << pub_key;
    pub_file.close();

    // Save private key
    std::ofstream pri_file(PRI_KEY_FILE, std::ios::out);
    if (!pri_file.is_open())
    {
        perror("pri key file open fail:");
        return;
    }
    pri_file << pri_key;
    pri_file.close();

    // Release memory
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);

    free(pri_key);
    free(pub_key);
}

std::string OpensslTool::ReadPublicKey(const std::string& PUB_KEY_FILE) {
    // Read public key
    std::string pub_key;
    std::ifstream pub_file(PUB_KEY_FILE, std::ios::in);
    if (!pub_file.is_open()) {
        return std::string();
    }

    pub_key = std::string((std::istreambuf_iterator<char>(pub_file)),
        std::istreambuf_iterator<char>());
    pub_file.close();

    return pub_key;
}

std::string OpensslTool::ReadPrivateKey(const std::string &PRI_KEY_FILE) {
    // Read private key
    std::string pri_key;

    std::ifstream pri_file(PRI_KEY_FILE, std::ios::in);
    if (!pri_file.is_open()) {
        return std::string();
    }

    pri_key = std::string((std::istreambuf_iterator<char>(pri_file)),
        std::istreambuf_iterator<char>());
    pri_file.close();

    return pri_key;
}

/*
@brief: private key encryption
@para: clear_text -[i] The clear text that needs to be encrypted
pri_key -[i] private key
@return: Encrypted data
**/
std::string OpensslTool::RsaPriEncrypt(const std::string &clear_text, const std::string &pri_key)
{
    std::string encrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);
    RSA* rsa = RSA_new();
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        BIO_free_all(keybio);
        return std::string("");
    }

    // Get the maximum length of the data block that RSA can process at a time
    int key_len = RSA_size(rsa);
    int block_len = key_len - 11; // Because the filling method is RSA_PKCS1_PADDING, so you need to subtract 11 from the key_len

                                    // Apply for memory: store encrypted ciphertext data
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    int pos = 0;
    std::string sub_str;
    // Encrypt the data in segments (the return value is the length of the encrypted data)
    while (pos < clear_text.length()) {
        sub_str = clear_text.substr(pos, block_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_private_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0) {
            encrypt_text.append(std::string(sub_text, ret));
        }
        pos += block_len;
    }

    // release memory  
    BIO_free_all(keybio);
    RSA_free(rsa);
    delete[] sub_text;

    return encrypt_text;
}

/*
@brief: public key decryption
@para: cipher_text -[i] encrypted ciphertext
pub_key -[i] public key
@return: decrypted data
**/
std::string OpensslTool::RsaPubDecrypt(const std::string & cipher_text, const std::string & pub_key)
{
    std::string decrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
    RSA *rsa = RSA_new();

    // Note--------Use the public key in the first format for decryption
    //rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    // Note--------Use the public key in the second format for decryption (we use this format as an example)
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    if (!rsa)
    {
        unsigned long err = ERR_get_error(); //Get the error number
        char err_msg[1024] = { 0 };
        ERR_error_string(err, err_msg); // Format: error:errId: library: function: reason
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        BIO_free_all(keybio);
        return decrypt_text;
    }

    // Get the maximum length of RSA single processing    
    int key_len = RSA_size(rsa);
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    std::string sub_str;
    int pos = 0;
    // Decrypt the ciphertext in segments    
    while (pos < cipher_text.length()) {
        sub_str = cipher_text.substr(pos, key_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_public_decrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0) {
            decrypt_text.append(std::string(sub_text, ret));
            printf("pos:%d, sub: %s\n", pos, sub_text);
            pos += key_len;
        }
    }
    // release memory      
    delete[] sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);
    return decrypt_text;
}

/*
@brief: public key encryption
@para: clear_text -[i] The clear text that needs to be encrypted
pri_key -[i] private key
@return: Encrypted data
**/
std::string OpensslTool::RsaPubEncrypt(const std::string &clear_text, const std::string &pub_key)
{
    std::string encrypt_text;
    BIO *keybio = BIO_new_mem_buf((unsigned char *)pub_key.c_str(), -1);
    RSA* rsa = RSA_new();
    // Note the public key in the first format
    //rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
    // Note the public key in the second format (here we take the second format as an example)
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

    // Get the maximum length of the data block that RSA can process at a time
    int key_len = RSA_size(rsa);
    int block_len = key_len - 11; // Because the filling method is RSA_PKCS1_PADDING, so you need to subtract 11 from the key_len

                                  // Apply for memory: store encrypted ciphertext data
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    int pos = 0;
    std::string sub_str;
    // Encrypt the data in segments (the return value is the length of the encrypted data)
    while (pos < clear_text.length()) {
        sub_str = clear_text.substr(pos, block_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_public_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0) {
            encrypt_text.append(std::string(sub_text, ret));
        }
        pos += block_len;
    }

    // release memory  
    BIO_free_all(keybio);
    RSA_free(rsa);
    delete[] sub_text;

    return encrypt_text;
}

/*
@brief: private key decryption
@para: cipher_text -[i] encrypted ciphertext
pub_key -[i] public key
@return: decrypted data
**/
std::string OpensslTool::RsaPriDecrypt(const std::string &cipher_text, const std::string &pri_key)
{
    std::string decrypt_text;
    RSA *rsa = RSA_new();
    BIO *keybio;
    keybio = BIO_new_mem_buf((unsigned char *)pri_key.c_str(), -1);

    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (rsa == nullptr) {
        unsigned long err = ERR_get_error(); //Get the error number
        char err_msg[1024] = { 0 };
        ERR_error_string(err, err_msg); // Format: error:errId: library: function: reason
        printf("err msg: err:%ld, msg:%s\n", err, err_msg);
        return std::string();
    }

    // Get the maximum length of RSA single processing
    int key_len = RSA_size(rsa);
    char *sub_text = new char[key_len + 1];
    memset(sub_text, 0, key_len + 1);
    int ret = 0;
    std::string sub_str;
    int pos = 0;
    // Decrypt the ciphertext in segments
    while (pos < cipher_text.length()) {
        sub_str = cipher_text.substr(pos, key_len);
        memset(sub_text, 0, key_len + 1);
        ret = RSA_private_decrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
        if (ret >= 0) {
            decrypt_text.append(std::string(sub_text, ret));
            printf("pos:%d, sub: %s\n", pos, sub_text);
            pos += key_len;
        }
    }
    // release memory  
    delete[] sub_text;
    BIO_free_all(keybio);
    RSA_free(rsa);

    return decrypt_text;
}

void demo() {
    // original plaintext  
    std::string src_text = "test begin\n this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! this is an rsa test example!!! \ntest end";

    std::string encrypt_text;
    std::string decrypt_text;

    // Generate key pair
    std::string pub_key;
    std::string pri_key;
    //OpensslTool::GenerateRSAKey(pub_key, pri_key);
    pub_key = OpensslTool::ReadPublicKey();
    pri_key = OpensslTool::ReadPrivateKey();
    printf("public key:\n");
    printf("%s\n", pub_key.c_str());
    printf("private key:\n");
    printf("%s\n", pri_key.c_str());

    //// Private key encryption-public key decryption
    encrypt_text = OpensslTool::RsaPriEncrypt(src_text, pri_key);
    printf("encrypt: len=%d\n", encrypt_text.length());
    decrypt_text = OpensslTool::RsaPubDecrypt(encrypt_text, pub_key);
    printf("decrypt: len=%d\n", decrypt_text.length());
    printf("decrypt: %s\n", decrypt_text.c_str());

    // Public key encryption-private key decryption
    encrypt_text = OpensslTool::RsaPubEncrypt(src_text, pub_key);
    printf("encrypt: len=%d\n", encrypt_text.length());
    decrypt_text = OpensslTool::RsaPriDecrypt(encrypt_text, pri_key);
    printf("decrypt: len=%d\n", decrypt_text.length());
    printf("decrypt: %s\n", decrypt_text.c_str());
}

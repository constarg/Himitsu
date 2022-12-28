#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "security.hh"

using namespace Himitsu;


Security::Security()
{
    // TODO - secure here the private fields.
}

Security::~Security()
{
    // TODO - free the memory.
}

const unsigned char *Security::get_sha256(const char *msg, size_t s_msg)
{
    unsigned char *byte_arr = (unsigned char *) malloc(sizeof(char) * SHA256_LEN);
    int err1, err2, err3;

    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();
    if (!ctx) return nullptr;

    err1 = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    err2 = EVP_DigestUpdate(ctx, msg, s_msg);
    err3 = EVP_DigestFinal_ex(ctx, byte_arr, NULL);

    EVP_MD_CTX_free(ctx);

    return (err1 != 1 || err2 != 1 ||
            err3 != 1)? nullptr : (const unsigned char *) byte_arr;
}

int Security::encrypt_data(unsigned char *dst, const unsigned char *data, 
                           int size, const unsigned char *key, const unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;
    int tmp_size = 0;
    int dst_size = 0;
    int err1, err2, err3;

    ctx  = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Enccypt the data using AES 256. 
    err1 = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    err2 = EVP_EncryptUpdate(ctx, dst, &dst_size, data, size);
    err3 = EVP_EncryptFinal(ctx, dst + tmp_size, &tmp_size);

    EVP_CIPHER_CTX_free(ctx);
    dst_size += tmp_size; // complete the size of encrypted data.
    
    return (err1 != 1 || err2 != 1 ||
            err3 != 1)? -1 : dst_size;
}

int Security::decrypt_data(unsigned char *dst, const unsigned char *data, 
                           int size, const unsigned char *key, const unsigned char *iv)
{
    EVP_CIPHER_CTX *ctx;
    int tmp_size = 0;
    int dst_size = 0;
    int err1, err2, err3;

    ctx  = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // Deccypt the data using AES 256.
    err1 = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    err2 = EVP_DecryptUpdate(ctx, dst, &dst_size, data, size);
    err3 = EVP_DecryptFinal(ctx, dst + tmp_size, &tmp_size);

    EVP_CIPHER_CTX_free(ctx);
    dst_size += tmp_size; // complete the size of encrypted data.
    
    return (err1 != 1 || err2 != 1 ||
            err3 != 1)? -1 : dst_size;
}

unsigned char *Security::get_random_bytes(int len)
{
    unsigned char *iv = (unsigned char *) malloc(sizeof(char) *
                                                 len); // 256 - bits, aes256

    RAND_bytes(iv, len);
    if (ERR_get_error() == 0) {
        return iv;
    }
    return nullptr;
}

unsigned char *Security::get_aes_iv()
{
    return this->get_random_bytes(IV_LEN);
}

int Security::get_master_pwd_size()
{
    return this->plock_enc_size;
}

const unsigned char *Security::get_master_pwd()
{
    return this->plock_enc;
}

const unsigned char *Security::get_master_used_key()
{
    return this->plock_key;
}

const unsigned char *Security::get_master_used_iv()
{
    return this->plock_iv;
}

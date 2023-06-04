#include <cstring>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/mman.h>

#include <math.h>

#include "security.hh"

using namespace Himitsu;

/**
 * PRIVATE MEMBERS
 */

/**
 * The implementation of the below methods 
 * is nessesery in order to prevent mulitple
 * syscalls of mlock and munlock.
 *
 * This method expects that the dst is already
 * an allocated space. Is used for the private
 * members on the Security class.
 */

int Security::get_random_bytes(unsigned char *dst, int len)
{ 
    RAND_bytes(dst, len);
    if (ERR_get_error() == 0) {
        
        return 0;
    }
    return -1;
}
            
int Security::get_aes_iv(unsigned char *dst)
{
    return get_random_bytes(dst, IV_LEN);
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

char *Security::decrypt_master_key()
{
    int err = 0;
    char *master = (char *) OPENSSL_malloc(sizeof(char) * PASSWD_MAX + 1);
    (void)memset(master, 0x0, PASSWD_MAX + 1);

    // lock memory.
    if (mlock(master, PASSWD_MAX) != 0) return nullptr;

    // decrypt.
    err = Security::decrypt_data((unsigned char *) master, 
                                 (const unsigned char *) this->plock_enc, 
                                 this->plock_enc_size, this->plock_key, 
                                 this->plock_iv);

    if (-1 == err) return nullptr;

    return master;
}

static inline int dispose_master_key(char *master)
{
    OPENSSL_cleanse(master, PASSWD_MAX + 1);
    if (munlock(master, PASSWD_MAX + 1) != 0) return -1;
    OPENSSL_free(master);
}

/**
 * PUBLIC MEMBERS
 */

Security::Security()
{
    this->plock_err = 0;
    // Allocate space for the sensitive data.
    this->plock_enc      = (unsigned char *) OPENSSL_malloc(sizeof(char) * ENC_MAX);
    this->plock_iv       = (unsigned char *) OPENSSL_malloc(sizeof(char) * IV_LEN);
    this->plock_key      = (unsigned char *) OPENSSL_malloc(sizeof(char) * AES_LEN);
    this->plock_enc_size = 0;

    // initialization.
    (void)memset(this->plock_enc, 0x0, ENC_MAX);
    (void)memset(this->plock_iv, 0x0, IV_LEN);
    (void)memset(this->plock_key, 0x0, AES_LEN);
    
    // lock to memory.
    this->plock_err += mlock(this->plock_enc, ENC_MAX);
    this->plock_err += mlock(this->plock_iv, IV_LEN);
    this->plock_err += mlock(this->plock_key, AES_LEN);
    this->plock_err += mlock(&this->plock_enc_size, sizeof(int));
}

Security::~Security()
{
    // dispose data.
    OPENSSL_cleanse(this->plock_enc, ENC_MAX);
    OPENSSL_cleanse(this->plock_iv, IV_LEN);
    OPENSSL_cleanse(this->plock_key, AES_LEN);
    OPENSSL_cleanse(&this->plock_enc_size, sizeof(int));

    // unlock memory.
    (void)munlock(this->plock_enc, ENC_MAX);
    (void)munlock(this->plock_iv, IV_LEN);
    (void)munlock(this->plock_key, AES_LEN);
    (void)munlock(&this->plock_enc_size, sizeof(int));

    // free memory.
    OPENSSL_free(this->plock_enc);
    OPENSSL_free(this->plock_iv);
    OPENSSL_free(this->plock_key);
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


int Security::encrypt_master_pwd(const char *master)
{
    if (this->plock_err != 0) return -1;

    Security::get_random_bytes(this->plock_key, AES_LEN); // Get a random sequence of bytes.
    Security::get_aes_iv(this->plock_iv); // Get the initialization vector.

    if (this->plock_key == nullptr ||
        this->plock_iv == nullptr) return -1;

    // encrypt master key.
    this->plock_enc_size = Security::encrypt_data(this->plock_enc, 
                                                  (const unsigned char *) master, 
                                                  strlen(master), this->plock_key, 
                                                  this->plock_iv);

    return 0;
}

char *Security::encrypt_data_using_master(unsigned char *enc_data, 
                                          unsigned char *user_iv, char *plaintext)
{
    char *master_key = decrypt_master_key();

    /*encrypt_data(dst, (const unsigned char*) plaintext,
                 strlen(plaintext), master_key, user_iv);*/
    // TODO - decrypt the master key
    // TODO - use the master key to encrypt the data.  
    return nullptr;
}

unsigned char *Security::get_random_bytes(int len)
{
    unsigned char *bytes = (unsigned char *) malloc(sizeof(char) *
                                                    len); // 256 - bits, aes256
    // TODO - PROTECT MEMORY.
    RAND_bytes(bytes, len);
    if (ERR_get_error() == 0) {
        return bytes;
    }
    return nullptr;
}

unsigned char *Security::get_aes_iv()
{
    return Security::get_random_bytes(IV_LEN);
}

int Security::password_entropy(size_t len, size_t range)
{
    return len * log2(range); 
}


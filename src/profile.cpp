#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>
#include <dirent.h>
#include <cstring>

#include "profile.h"

#include <iostream>

using namespace Himitsu;


#define IV_LEN          0x10  // 127 - bits, 16 bytes. (initialization vector)
#define AES_LEN         0x20  // 256 - bits, 32 bytes.
#define SHA256_LEN      0x20  // 256 - bits, 32 bytes. 

// *record errors*
#define REC_EXIST       -0x2  // The requested record already exist.
#define BAD_CRED        -0x3  // Bad username of password.

#define PROFILE_LOC()                           \
    + "/"                                       \
    +  ".local/share/Himitsu/profiles/"         

#define PROFILE_LOG_INFO()                      \
    + "/"                                       \
    + ".local/share/Himitsu/logins/"            

#define RECORD_LOC()                            \
    + "/"                                       \
    + ".local/share/Himitsu/records/"

/**
 *  This structure is used to represent the
 *  informations in a login file. It is easier
 *  to read a structure than to remember how the
 *  file is structued.
 */
struct logins 
{
    unsigned char l_username[SHA256_LEN];    // The usernmae of the profile.
    unsigned char l_lock[SHA256_LEN];        // The master password of the profile.
    unsigned char l_iv[IV_LEN];              // The initialization vector of the profile.
};

/**
 *  A record is just an online account
 *  that is stored in the password manager
 *  database.
 */
struct record
{
    unsigned char *r_username;               // The username of the record.
    unsigned char *r_password;               // The password of the record.
};

/**
 * *********************
 *  Non Members functions
 * *********************
 */
/**
 * *get_login_info* functions get's the usernmae, password and 
 * initialization vector from a login file, associated with 
 * the profile.
 * 
 * @param dst The destination where we put the results
 * @param pname The profile name.
 */
static int get_login_info(struct logins *dst, std::string pname)
{
    std::string home_prefix = getenv("HOME");
    std::string login_location = home_prefix + PROFILE_LOG_INFO() + pname; // The location whre the logins for profiles is stored.
    int fd = open(login_location.c_str(), O_RDONLY);
    if (fd == -1) return -1;

    struct logins login_info;
    memset(&login_info, 0x0, sizeof(login_info));

    // Get the username.
    if (read(fd, login_info.l_username, SHA256_LEN) == -1) return -1;
    if (read(fd, login_info.l_lock, SHA256_LEN) == -1) return -1;
    if (read(fd, login_info.l_iv, IV_LEN) == -1) return -1;

    memcpy(dst, &login_info, sizeof(login_info));
    close(fd);
    return 0;
}

/**
 *  *is_rec_exists* function checks 
 *  if a record already exists.
 */
static bool is_rec_exists(std::string serv)
{
    std::string home_prefix = getenv("HOME");
    std::string record_location = home_prefix + RECORD_LOC() + serv;

    std::ofstream rfile;

    rfile.open(record_location, std::ios::in);
    // check if the file exist.
    if (rfile.is_open()) {
        rfile.close();
        return true;
    }

    return false;
}

/**
 * *get_record* function get's the username and the password
 * of a specific record. To find the right username and password
 * the password manager must know the service.
 *
 * @param dst Where the record is stored in success.
 * @param serv The service of interest.
 * @return 0 on success or -1 on failrure.
 */
static int get_record(struct record *dst, std::string serv)
{
    // TODO - get the line at the specific file.
    // The file is created using the serv name.
}


static int save_record(const struct record *src, std::string serv)
{
    // check if the service already exist.
    if (is_rec_exists(serv)) return REC_EXIST;

    // if the record doesn't exists.
    // Check if anything is wrong in username or password.
    if (src->r_username == NULL ||
        src->r_password == NULL) return BAD_CRED;

    //Profile::encrypt_data(unsigned char *dst, const unsigned char *data, 
    //                      int size, const unsigned char *key, const unsigned char *iv)

    // TODO - decrypt master password, to use it below.
    // encrypt record.
    // The size of the encrypted username and encrypted username.
    char enc_username[ENC_MAX];
    //int usern_enc_size = Profile::encrypt_data(enc_username, src->r_username,);
    // The size of the encrypted password and encrypted password.
    char enc_password[ENC_MAX];
    int passwd_enc_size = ;

    // convert username and password to hex.
    char *hex_username = OPENSSL_buf2hexstr();
}

static int edit_record(const struct record *src, std::string serv)
{

}

static inline unsigned char *get_random_bytes(int len)
{
    unsigned char *iv = (unsigned char *) malloc(sizeof(char) *
                                                 len); // 256 - bits, aes256

    RAND_bytes(iv, len);
    if (ERR_get_error() == 0) {
        return iv;
    }
    return nullptr;
}

// Get an random initialization vector for aes.
static inline unsigned char *get_aes_iv()
{
    return get_random_bytes(IV_LEN);
}


/**
 * ********************
 *    Private Methods
 * ********************
 */
const unsigned char *Profile::get_sha256(const char *msg, size_t s_msg)
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

int Profile::encrypt_data(unsigned char *dst, const unsigned char *data, 
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

int Profile::decrypt_data(unsigned char *dst, const unsigned char *data, 
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

/**
 * ********************
 *    Public Methods
 * ********************
 */

Profile::Profile()
{
    this->status    = DISCONECTED;
    this->plock_key = nullptr;
    this->plock_iv  = nullptr;
}


bool Profile::mk_new_prof(std::string pname, std::string username,
                                 std::string lock)
{
    std::string home_prefix = getenv("HOME");
    std::string prof_location = home_prefix + PROFILE_LOC() + pname; // The location where the profiles is stored.
    std::string login_location = home_prefix + PROFILE_LOG_INFO() + pname; // The location whre the logins for profiles is stored.
    
    std::ofstream pfile;

    int prof_fd;
    int err1, err2, err3;

    const unsigned char *username_sha256 = nullptr;
    const unsigned char *lock_sha256 = nullptr;
    const unsigned char *iv_aes = nullptr;

    pfile.open(prof_location, std::ios::in);
    // check if the file already exist.
    if (pfile.is_open()) {
        pfile.close();
        return false;
    }
    
    pfile.clear(); // reset to goodbit.
    // make the file asociated with the profile pname.
    pfile.open(prof_location, std::ios::out);
    if (!pfile.good()) return false;
    pfile.close();

    // Create the login file, asociated with the profile.
    // If there is not any profile, even if there is a login, clean
    // it's contents and rewrite it.
    prof_fd = open(login_location.c_str(), O_WRONLY | O_APPEND
                                         | O_CREAT, 0700);
    // get the hashes
    username_sha256 = Profile::get_sha256(username.c_str(), username.size());
    lock_sha256     = Profile::get_sha256(lock.c_str(), lock.size());
    iv_aes          = get_aes_iv();

    if (!username_sha256 || !lock_sha256
        || !iv_aes) {
        free((void *) username_sha256);
        free((void *) lock_sha256);
        free((void *) iv_aes);
        close(prof_fd);
        return false;
    } 

    err1 = write(prof_fd, (const void *) username_sha256, SHA256_LEN);
    err2 = write(prof_fd, (const void *) lock_sha256, SHA256_LEN);
    err3 = write(prof_fd, (const void *) iv_aes, IV_LEN);

    free((void *) username_sha256);
    free((void *) lock_sha256);
    free((void *) iv_aes);

    close(prof_fd);

    return (err1 == -1 || err2 == -1
            || err3 == -1)? false : true;
}

bool Profile::del_prof(std::string pname, std::string sername, 
                       std::string lock)
{
    // TODO - decide where the account info is stored.
    return true;    
}

std::vector<std::string> Profile::show_profs()
{
    std::vector<std::string> profiles;
    std::string profile_str;
    std::string home_prefix = getenv("HOME");
    std::string profile_loc = home_prefix + "/.local/share/Himitsu/profiles/";

    DIR *dir;
    struct dirent *profile;

    dir = opendir(profile_loc.c_str());
    if (dir == nullptr) return profiles;

    while ((profile = readdir(dir)) 
            != nullptr) {
        if (profile->d_type == DT_REG) {
            profile_str = profile->d_name;
            profiles.push_back(profile_str);
        }
    }

    closedir(dir);
    return profiles;
}

std::string Profile::random_passwd()
{
    return "";
}

void Profile::connect(std::string username, const char *lock,
                      std::string pname)
{
    if (is_connected()) disconnect();
   
    // From user.
    const unsigned char *in_username_sha256; // hashed input username.
    const unsigned char *in_lock_sha256;     // hashed input lock.
    // From system.
    struct logins login;                // The hashed logins.

    int cmp = 0;

    // Get login info.
    if (get_login_info(&login, pname) == -1) return;

    // hash the input.
    in_username_sha256 = Profile::get_sha256(username.c_str(), username.size());
    in_lock_sha256 = Profile::get_sha256(lock, strlen(lock));
    if (!in_username_sha256 || !in_lock_sha256) return;

    // compare the hashes from the system and the input hashes.
    cmp  = memcmp(in_username_sha256, login.l_username, SHA256_LEN);
    cmp += memcmp(in_lock_sha256, login.l_lock, SHA256_LEN);
    free((void *) in_username_sha256);
    free((void *) in_lock_sha256);
    // check if the  hashes are equal.
    if (cmp != 0) return;

    // if the above stament didn't return, when the user put the right credentials.
    // before check the account as connected we have to do a few jobs.
    // encrypt the lock (a.k.a master password) using random bytes.
    this->plock_key = get_random_bytes(AES_LEN); // this behaves as just random bytes. // TODO - this value must be freed.
    this->plock_iv  = get_aes_iv();              // behave as the actual iv.           // TODO - this value must be freed.

    if (this->plock_iv == nullptr ||
        this->plock_key == nullptr) return;

    // encrypt lock.
    this->plock_enc_size = Profile::encrypt_data(this->plock_enc, 
                                                 (const unsigned char *) lock, 
                                                 strlen(lock), this->plock_key, 
                                                 this->plock_iv);
    // If all of the above actions are done,
    // then the user is connected.
    this->status = CONNECTED;
    this->pname  = pname;
}

void Profile::disconnect()
{
    // Reset class members.
    passwords.clear();
    services.clear();
    pname = "";
    status = DISCONECTED;
}
      
bool Profile::is_connected() const
{
    return this->status;
}

          
std::string Profile::get_active_prof()
{
    return this->pname;
}
           
int Profile::count_pwds() const
{
    return this->passwords.size();
}
         
std::string Profile::get_pwd(std::string serv) const
{
    return this->passwords.at(serv);
}
           

std::vector<std::string> Profile::get_list_of_services() const
{
    return this->services;
}
            

bool Profile::add_pwd(std::string serv_name, std::string username, const char *pwd)
{
    //return this->passwords.emplace(std::make_pair(serv_name, pwd)).second; // returns if the insertion is done or not.
    return true;
}



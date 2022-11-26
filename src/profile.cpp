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


#define PROFILE_LOC()                           \
    + "/"                                       \
    +  ".local/share/Himitsu/profiles/"         \

#define PROFILE_LOG_INFO()                      \
    + "/"                                       \
    + ".local/share/Himitsu/logins/"            \

/**
 *  This structure is used to represent the
 *  informations in a login file. It is easier
 *  to read a structure than to remember how the
 *  file is structued.
 */
struct logins 
{
    unsigned char username[32];    // The usernmae of the profile.
    unsigned char lock[32];        // The master password of the profile.
    unsigned char iv[32];          // The initialization vector of the profile.
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
    if (read(fd, login_info.username, 32) == -1) return -1;
    if (read(fd, login_info.lock, 32) == -1) return -1;
    if (read(fd, login_info.iv, 32) == -1) return -1;

    memcpy(dst, &login_info, sizeof(login_info));
    close(fd);
    return 0;
}

// Get an random initialization vector for aes.
static inline unsigned char *get_aes_iv(int len)
{
    unsigned char *iv = (unsigned char *) malloc(sizeof(char) *
                                                 len); // 256 - bits, aes256

    RAND_bytes(iv, len);
    if (ERR_get_error() == 0) {
        return iv;
    }
    return nullptr;
}

/**
 * ********************
 *    Private Methods
 * ********************
 */
const unsigned char *Profile::get_sha256(const char *msg, size_t s_msg)
{
    unsigned char *byte_arr = (unsigned char *) malloc(sizeof(char) * 32);

    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, msg, s_msg);
    EVP_DigestFinal_ex(ctx, byte_arr, NULL);

    EVP_MD_CTX_free(ctx);

    return (const unsigned char *) byte_arr;
}

unsigned char *Profile::encrypt_data(const unsigned char *lock, const unsigned char *iv,
                                     const unsigned char *data, int size)
{
    unsigned char *enc = (unsigned char *) malloc(sizeof(char) * 48);
    memset(enc, 0x0, 48);
    int enc_size = 0;
    int len = 0;

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, lock, iv);
    EVP_EncryptUpdate(ctx, enc, &len, data, size);
    EVP_EncryptFinal(ctx, enc + len, &enc_size);

    std::cout << enc_size + len << std::endl;

    int fd = open("/home/rounnus/test/out2.txt", O_WRONLY);
    write(fd, enc, enc_size + len);
    close(fd);

    EVP_CIPHER_CTX_free(ctx);
    return enc; 
}

// TODO - return a pair of int and the decrypt data
unsigned char *Profile::decrypt_data(std::string enc_data)
{
    return nullptr;
}

/**
 * ********************
 *    Public Methods
 * ********************
 */

Profile::Profile()
{
    this->status = DISCONECTED;
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
    iv_aes          = get_aes_iv(16);

    err1 = write(prof_fd, (const void *) username_sha256, 32);
    err2 = write(prof_fd, (const void *) lock_sha256, 32);
    err3 = write(prof_fd, (const void *) iv_aes, 16);

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

    // Get login info.
    if (get_login_info(&login, pname) == -1) return;

    // hash the input.
    in_username_sha256 = Profile::get_sha256(username.c_str(), username.size());
    in_lock_sha256 = Profile::get_sha256(lock, strlen(lock));

    // compare the hashes from the system and the input hashes.
    if (memcmp(in_username_sha256, login.username, 32) != 0) return;
    if (memcmp(in_lock_sha256, login.lock, 32) != 0) return;

    // if the above stament didn't return, when the user put the right credentials.
    // before check the account as connected we have to do a few jobs.
    // encrypt the lock (a.k.a master password) using random bytes.
    this->plock_key = get_aes_iv(32); // behave this, as just random bytes.
    this->plock_iv  = get_aes_iv(16); // behave as the actual iv.

    if (this->plock_iv == nullptr ||
        this->plock_key == nullptr) return;

    // encrypt lock.
    this->plock_enc = encrypt_data(this->plock_key, this->plock_iv,
                                   (unsigned char *) lock, strlen(lock));
  
    int fd = open("/home/rounnus/test/key.txt", O_WRONLY | O_CREAT);
    write(fd, plock_key, 32);
    close(fd);

    fd = open("/home/rounnus/test/iv.txt", O_WRONLY | O_CREAT);
    write(fd, plock_iv, 16);
    close(fd);

    // If all of the above actions are done,
    // then the user is connected.
    this->status = CONNECTED;
    this->pname  = pname;
    free((void *) in_username_sha256);
    free((void *) in_lock_sha256);
    // TODO - only test, DELETE THIS.
    free((void *) plock_key);
    free((void *) plock_iv);
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
            

bool Profile::add_pwd(std::string serv_name, std::string pwd)
{
    return this->passwords.emplace(std::make_pair(serv_name, pwd)).second; // returns if the insertion is done or not.
}



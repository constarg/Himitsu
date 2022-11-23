#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>

#include "profile.h"


using namespace Pwd_Manager;


#define PROFILE_LOC()                           \
    + "/"                                       \
    +  ".local/share/pwd_manager/profiles/"     \

#define PROFILE_LOG_INFO()                      \
    + "/"                                       \
    + ".local/share/pwd_manager/logins/"        \

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
static int get_login_info(struct login_info *dst, std::string pname)
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

// Get an initialization vector for aes.
static inline unsigned char *get_aes_iv()
{
    static unsigned char iv[32]; // 256 - bits, aes256

    RAND_bytes(iv, 32);
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

std::string Profile::encrypt_data(std::string username, std::string lock,
                                  std::string serv)
{
    return ""; // TODO - remove this and make the function.
}

std::vector<std::string> decrypt_data(std::string enc_data)
{
    return std::vector<std::string>(); // TODO - remove this and make the functon.
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
                                         | O_CREAT);
    // get the hashes
    username_sha256 = get_sha256(username.c_str(), username.size());
    lock_sha256     = get_sha256(lock.c_str(), lock.size());
    iv_aes          = get_aes_iv();

    err1 = write(prof_fd, (const void *) username_sha256, 32);
    err2 = write(prof_fd, (const void *) lock_sha256, 32);
    err3 = write(prof_fd, (const void *) iv_aes, 32);

    free((void *) username_sha256);
    free((void *) lock_sha256);
    
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


bool Profile::search_prof(const std::string pname) const
{
    // TODO - decide where the account info is stored.
    return 0;
}


void Profile::connect(std::string username, std::string lock, 
                      std::string pname)
{
    if (is_connected()) disconnect();

    // open " connect " to the profile.
    // TODO - decide where the account info is stored.
}

void Profile::disconnect()
{
    // Reset class members.
    passwords.clear();
    services.clear();
    pname = "";
    status = DISCONECTED;
}
      
inline bool Profile::is_connected() const
{
    return this->status;
}

          
inline std::string Profile::get_active_prof()
{
    return this->pname;
}
           
inline int Profile::count_pwds() const
{
    return this->passwords.size();
}
         
inline std::string Profile::get_pwd(std::string serv) const
{
    return this->passwords.at(serv);
}
           

inline std::vector<std::string> Profile::get_list_of_services() const
{
    return this->services;
}
            

inline bool Profile::add_pwd(std::string serv_name, std::string pwd)
{
    return this->passwords.emplace(std::make_pair(serv_name, pwd)).second; // returns if the insertion is done or not.
}

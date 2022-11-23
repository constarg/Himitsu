#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <openssl/evp.h>

#include "profile.h"

using namespace Pwd_Manager;


#define PROFILE_LOC()                           \
    + "/"                                       \
    +  ".local/share/pwd_manager/profiles/"     \

#define PROFILE_LOG_INFO()                      \
    + "/"                                       \
    + ".local/share/pwd_manager/logins/"        \

/**
 * ********************
 *    Private Methods
 * ********************
 */

const char *Profile::get_sha256(const char *msg, size_t s_msg)
{
    unsigned char byte_arr[32] = {0};
    char *result = (char *) malloc(sizeof(char) * 65);

    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, msg, s_msg);
    EVP_DigestFinal_ex(ctx, byte_arr, NULL);

    EVP_MD_CTX_free(ctx);

    for (int h = 0; h < 32; h++) {
        sprintf(result + h * 2, "%02x", byte_arr[h]);
    }

    return (const char *) result;
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

    const char *username_sha256 = nullptr;
    const char *lock_sha256 = nullptr;

    this->pfile.open(prof_location, std::ios::in);
    // check if the file already exist.
    if (pfile.is_open()) {
        this->pfile.close();
        this->pfile.clear();
        return false;
    }
    
    this->pfile.clear(); // reset to goodbit.
    // make the file.
    this->pfile.open(prof_location, std::ios::out);
    if (!this->pfile.good()) {
        this->pfile.clear();
        return false;
    }
    this->pfile.close();
    this->pfile.clear();

    // Create the login file, asociated with the profile.
    // If there is not any profile, even if there is a login, clean
    // it's contents and rewrite it.
    this->pfile.open(login_location, std::ios::out |
                                     std::ios::trunc);
    // build the login file.
    username_sha256 = get_sha256(pname.c_str(), pname.size());
    lock_sha256     = get_sha256(lock.c_str(), lock.size());

    // store the login infos.
    this->pfile << username_sha256 
                << ":"
                << lock_sha256;

    free((void *) username_sha256);
    free((void *) lock_sha256);

    this->pfile.close();
    this->pfile.clear();
    return true;
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
    pfile.clear();
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

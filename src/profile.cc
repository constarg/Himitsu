#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>
#include <dirent.h>
#include <cstring>
#include <malloc.h>

#include "profile.hh"
#include "security.hh"

#include <iostream>

using namespace Himitsu;


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
    std::string home_prefix    = getenv("HOME");
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
    std::string home_prefix     = getenv("HOME");
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
    return 0;
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

    // The size of the encrypted username and encrypted username.
    char enc_username[ENC_MAX];
    int username_enc_size;
    //int usern_enc_size = Profile::encrypt_data(enc_username, src->r_username,);
    // The size of the encrypted password and encrypted password.
    char enc_password[ENC_MAX];
    int passwd_enc_size;

    // storage for converted to hex values.
    char *hex_username;
    char *hex_password;

    // Get master password.
    // TODO - protect the area used to store master password.
    return 0;
}

static int edit_record(const struct record *src, std::string serv)
{

    return 0;
}

/**
 * ********************
 *    Public Methods
 * ********************
 */

Profile::Profile()
{
    this->status           = DISCONECTED;
    this->security_manager = new Security(); 
}

Profile::~Profile()
{
    delete this->security_manager;
}

bool Profile::mk_new_prof(std::string pname, std::string username,
                          std::string lock)
{
    std::string home_prefix    = getenv("HOME");
    std::string prof_location  = home_prefix + PROFILE_LOC() + pname; // The location where the profiles is stored.
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
    username_sha256 = Security::get_sha256(username.c_str(), username.size());
    lock_sha256     = Security::get_sha256(lock.c_str(), lock.size());
    iv_aes          = Security::get_aes_iv();

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

const char *Profile::random_passwd(size_t len, 
                                   unsigned char *enable_bits) {
    // TODO - ask for length.
    // Set of alphabet lower case characters.
    char lower_case[26] = {
        'a','b','c','d','e',
        'f','g','h','i','j',
        'k','l','m','n','o',
        'p','q','r','s','t',
        'u','v','w','x','y',
        'z'
    };

    // Set of alphabet upper case characters.
    char upper_case[26] = {
        'A','B','C','D','E',
        'F','G','H','I','J',
        'K','L','M','N','O',
        'P','Q','R','S','T',
        'U','V','W','X','Y',
        'Z'
    };

    // Set of numbers.
    char numbers[10] = {
        '0', '1', '2', '3',
        '4', '5', '6', '7',
        '8', '9'
    };

    // Set of special characters.
    char special[8] = {
        '!', '@', '#', '$', 
        '%', '^', '&', '*'
    };

    // Set of all 4 sets.
    char *sets[4] = {
        lower_case, upper_case,
        numbers, special
    };

    char *generated_pwd = (char *) malloc(sizeof(char) * len + 1);
    memset(generated_pwd, 0x0, len + 1);
    size_t curr_pwd_size = 0;
    
    unsigned char *sel_set = 0; // select set.
    unsigned char *sel_ch  = 0; // select character.

    for (curr_pwd_size = 0; curr_pwd_size < len; ) {
        // in order to have right bounds.
        // TODO - check for errors that may occur from get_random_bytes.
        
        sel_set = Security::get_random_bytes(1); // get a random byte.
        sel_ch = Security::get_random_bytes(1);
      
        if (sel_set == nullptr || sel_ch == nullptr) {
            free(generated_pwd);
            free(sel_set);
            free(sel_ch);
            return NULL;
        }

        if ((short)(*sel_set & 0x3) == 0 && LOWER_EN(*enable_bits)) {
            *sel_ch = (*sel_ch & 0x1F) % 0x1A; // mod with 26 in order to stay in bounds. 
        } else if ((short)(*sel_set & 0x3) == 1 && UPPER_EN(*enable_bits)) {
            *sel_ch = (*sel_ch & 0x1F) % 0x1A;
        } else if ((short)(*sel_set & 0x3) == 2 && NUMBER_EN(*enable_bits)) {
            *sel_ch = (*sel_ch & 0x1F) % 10;
        } else if ((short)(*sel_set & 0x3) == 3 && SPECIAL_EN(*enable_bits)) {
            *sel_ch = (*sel_ch & 0x1F) % 8;
        } else {
            free(sel_set);
            free(sel_ch);
            continue;
        }

        generated_pwd[curr_pwd_size++] = sets[(short)*sel_set & 0x3][(short)*sel_ch];
        free(sel_set);
        free(sel_ch);
    }

    return generated_pwd;
}

void Profile::connect(std::string username, const char *lock,
                      std::string pname)
{
    if (is_connected()) disconnect();
   
    // From user.
    const unsigned char *in_username_sha256; // hashed input username.
    const unsigned char *in_lock_sha256;     // hashed input lock.
    // From system.
    struct logins login;                     // The hashed logins.

    int cmp = 0;

    // Get login info.
    if (get_login_info(&login, pname) == -1) return;

    // hash the input.
    in_username_sha256 = Security::get_sha256(username.c_str(), username.size());
    in_lock_sha256     = Security::get_sha256(lock, strlen(lock));
    in_lock_sha256     = Security::get_sha256(lock, strlen(lock));

    // compare the hashes from the system and the input hashes.
    cmp  = memcmp(in_username_sha256, login.l_username, SHA256_LEN);
    cmp += memcmp(in_lock_sha256, login.l_lock, SHA256_LEN);
    free((void *) in_username_sha256);
    free((void *) in_lock_sha256);
    // check if the  hashes are equal.
    if (cmp != 0) return;

    // encrypt the master password.
    if (this->security_manager->encrypt_master_pwd(lock) != 0) return;

    // if the above stament didn't return, when the user put the right credentials.
    // before check the account as connected we have to do a few jobs.
    // encrypt the lock (a.k.a master password) using random bytes.
    /*Security::plock_key = Security::get_random_bytes(AES_LEN); // this behaves as just random bytes. // TODO - this value must be freed.
    Security::plock_iv  = Security::get_aes_iv();              // behave as the actual iv.           // TODO - this value must be freed.

    if (Security::plock_iv == nullptr ||
        Security::plock_key == nullptr) return;

    // encrypt lock.
    Security::plock_enc_size = Security::encrypt_data(Security::plock_enc, 
                                                     (const unsigned char *) lock, 
                                                      strlen(lock), Security::plock_key, 
                                                      Security::plock_iv);*/
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


#include <memory.h>

#include "profile.h"


using namespace Pwd_Manager;


/**
 * ********************
 *    Private Methods
 * ********************
 */

void Profile::update_profile()
{

}

std::string Profile::encrypt_data(const std::string &username, 
                                  const std::string &lock,
                                  const std::string &serv)
{
    return ""; // TODO - remove this and make the function.
}

std::vector<std::string> decrypt_data(const std::string enc_data)
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


bool Profile::mk_new_prof(const std::string &pname, 
                          const std::string &username,
                          const std::string &lock) const
{
    // TODO - decide where to store the account info.
    return true;
}

inline bool Profile::del_prof(const std::string &pname, 
                              const std::string username, 
                              const std::string &lock)
{
    // TODO - decide where the account info is stored.
    return true;    
}


bool Profile::search_prof(const std::string &pname) const
{
    // TODO - decide where the account info is stored.
    return 0;
}


void Profile::connect(const std::string &username, 
                      const std::string &lock, 
                      const std::string &pname)
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
         
inline std::string Profile::get_pwd(const std::string &serv) const
{
    return this->passwords.at(serv);
}
           

inline std::vector<std::string> Profile::get_list_of_services() const
{
    return this->services;
}
            

inline bool Profile::add_pwd(std::string &serv_name, std::string &pwd)
{
    return this->passwords.emplace(std::make_pair(serv_name, pwd)).second; // returns if the insertion is done or not.
}

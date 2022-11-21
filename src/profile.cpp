
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


/**
 * ********************
 *    Public Methods
 * ********************
 */
Profile::Profile()
{

}

Profile::~Profile()
{

}

int Profile::mk_new_prof(const std::string &pname, 
                         const std::string &username,
                         const std::string &lock) const
{
    return 0;
}

int Profile::del_prof(const std::string &pname, 
                      const std::string username, 
                      const std::string &lock)
{
    return 0;
}


int Profile::search_prof(const std::string &pname) const
{
    return 0;
}


void Profile::connect(const std::string &username, 
                      const std::string &lock, 
                      const std::string &pname)
{

}

void Profile::disconnect()
{

}
      
inline bool Profile::is_connected() const
{
}

          
inline std::string Profile::get_active_prof()
{
}
           
inline int Profile::count_pwds() const
{
}
         
inline std::string& Profile::get_pwd(std::string &serv) const
{
}
           

inline std::vector<std::string> Profile::get_list_of_services() const
{
}
            

int Profile::add_pwd(std::string &serv_name, std::string &pwd)
{
}

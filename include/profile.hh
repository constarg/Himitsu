#ifndef PROFILE_H
#define PROFILE_H

#include <string>
#include <map>
#include <vector>
#include <fstream>

#include "security.hh"

#define CONNECTED   true
#define DISCONECTED false

#define PASSWD_MAX  32
#define ENC_MAX     128



namespace Himitsu 
{

    class Profile {
        private:
            // Data fileds.
            std::map<std::string, std::string> passwords; // The encrypted passwords.
            std::vector<std::string> services;            // All the unvailable services.
            std::string pname;                            // The name of the file that is acosiated with the profile.
            bool status;                                  // The status of the profile, connected or disconnected.

            Security *security_manager;                   // The security functions.

        public:
            Profile();
            ~Profile();
            /**
             * *mk_new_prof* method creates a new account
             * @param pname The name of the account.
             * @param username The username of the account.
             * @param lock The master password of the account.
             */
            static bool mk_new_prof(std::string pname, std::string username,
                                    std::string lock);
            /**
             * *del_prof* method deletes an account.
             * @param pname The name of the account.
             * @param username The username of the account.
             * @param lock The master password of the account.
             */
            static bool del_prof(std::string pname, std::string username, 
                                 std::string lock);

            /**
             * *random_passwd* generates a random password
             * and return the result.
             */
            static std::string random_passwd();

            /**
             * *search_prof* method displays all the unvailable
             * profiles in the system.
             */
            static std::vector<std::string> show_profs();

            /**
             * *connect* method connects to an existing account.
             * Connect assumes that the lock's (a.k.a master password) 
             * address remain always!! in memory. Before calling connect
             * there was a call of mlock, to lock up the address in memory.
             *
             * @param username The usernmae The username of the account.
             * @param lock The master password of the account.
             * @param pname The name of the account.
             */
            void connect(std::string username, const char *lock, std::string pname);

            /**
             * *disconnect* method disconnects from an connected account.
             */
            void disconnect();

            /**
             * *is_connected* method checks if there is any connected
             * account at the moment.
             */
            bool is_connected() const;

            /**
             * *get_active_prof* method returns the currently
             * connected profile.
             */
            std::string get_active_prof();

            /**
             * *get_pwd* method retrieves the password of the
             * specific service.
             * @param serv The service.
             */
            std::string get_pwd(std::string serv) const;

            /**
             * *get_list_of_services* returns all the 
             * services that exists in the password list.
             */
            std::vector<std::string> get_list_of_services() const;

            /**
             * *count_pwds* method counts the number of passwords in
             * an connected account.
             */
            int count_pwds() const;

            /**
             * *add_pwd* method adds an new password in the 
             * list.
             * @param serv_name The name of the service.
             * @param pwd The password.
             */
            bool add_pwd(std::string serv_name, std::string username, const char *pwd);
    };
}

#endif

#ifndef PROFILE_H
#define PROFILE_H

#include <string>
#include <map>
#include <vector>

namespace Pwd_Manager {
    class Profile {
        private:
            std::map<std::string, std::string> passwords;
            std::vector<std::string> services;

            // TODO - add here a encrypt and descrypt method.
            void update_profile();

        public:
            Profile();
            ~Profile();
            /**
             * *mk_new_prof* method creates a new account
             * @param pname The name of the account.
             * @param username The username of the account.
             * @param lock The master password of the account.
             */
            int mk_new_prof(const std::string &pname, const std::string &username,
                            const std::string &lock) const;
            /**
             * *del_prof* method deletes an account.
             * @param pname The name of the account.
             * @param username The username of the account.
             * @param lock The master password of the account.
             */
            int del_prof(const std::string &pname, const std::string username, 
                         const std::string &lock);
            /**
             * *search_prof* method searches for an existing account
             * @param panme The accout to search.
             */
            int search_prof(const std::string &pname) const;
            /**
             * *connect* method connects to an existing account.
             * @param username The usernmae The username of the account.
             * @param lock The master password of the account.
             * @param pname The name of the account.
             */
            void connect(const std::string &username, const std::string &lock, 
                         const std::string &pname);
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
             * *count_pwds* method counts thw number of passwords in
             * an connected account.
             */
            int count_pwds() const;
            /**
             * *get_pwd* method retrieves the password of the
             * specific service.
             * @param serv The service.
             */
            std::string &get_pwd(std::string &serv) const;
            /**
             * *get_list_of_services* returns all the 
             * services that exists in the password list.
             */
            std::vector<std::string> get_list_of_services() const;
            /**
             * *add_pwd* method adds an new password in the 
             * list.
             * @param serv_name The name of the service.
             * @param pwd The password.
             */
            int add_pwd(std::string &serv_name, std::string &pwd);
    };
}

#endif

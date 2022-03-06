#ifndef password_manager_h 
#define password_manager_h

#include <string>
#include <list>
#include <prof/Profile.h>


class PasswordManager
{
	private:
		Profile *profile;
	public:
		PasswordManager(const Profile *profile);
		void create_profile() const;
		void create_record(const std::string& account_name, const std::string& passwd) const;
		void delete_record(const std::string& account_name) const;
		void get_password(const std::string& account_name) const;
		void change_password(const std::string& account_name, const std::string& new_passwd) const;
		std::list<std::string> get_records() const;
};


#endif

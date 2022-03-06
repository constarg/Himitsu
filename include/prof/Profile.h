#ifndef profile_h
#define profile_h

#include <string>
#include <list>

class Profile
{
	private:
		std::string username;
		std::string master_passwd;
	public:
		Profile(const std::string& username, const std::string& master_passwd);
		std::string get_username() const;
		std::string get_master_passwd() const;
		void set_username(const std::string& username);
		void set_passwd(const std::string& passwd);
};

extern std::list<std::string> get_profiles();


#endif

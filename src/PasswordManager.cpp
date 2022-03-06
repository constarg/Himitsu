#include <passwdm/PasswordManager.h>



PasswordManager::PasswordManager(const Profile *profile)
{

}

void PasswordManager::create_profile() const 
{

}

void PasswordManager::create_record(const std::string& account_name,
									const std::string& passwd) const 
{

}

void PasswordManager::delete_record(const std::string& account_name) const
{

}

void PasswordManager::get_password(const std::string& account_name) const
{

}

void PasswordManager::change_password(const std::string& account_name, 
									  const std::string& new_passwd) const
{

}

std::list<std::string> PasswordManager::get_records() const
{

}


#include <cstring>
#include <iostream>
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "profile.h"

// Terminal modes.
#define HIDE 1
#define SHOW 2


static int help()
{
    // TODO - help.
    return 0;
}

static void manager_prompt(Himitsu::Profile &profile, 
                           std::string username)
{
    std::string input;
    int passwd_count = 0;

    std::cout << "Welcome back, " << username
              << std::endl
              << "Connected Profile: "
              << profile.get_active_prof()
              << std::endl;

    while (true) {
        std::cout << "(" << profile.get_active_prof() << ")"
                  <<  " => ";
        std::cin >> input;
        std::cout << std::endl;
 
        if (input == "help") {
            help();
        } else if (input == "disconnect") {
            profile.disconnect();
            std::cout << "Disconected" << std::endl;
            return;
        } else if (input == "count-passwds") {
            passwd_count = profile.count_pwds();
            std::cout << passwd_count << std::endl;
        } else if (input == "get-passwd") {
            std::cout << "Please type the name"
                      << "of the service (example: Facebook).";
            std::cout << "Service: ";
            std::cin  >> input;
            
            // Get the password for the specific service.
            try {
                std::cout << profile.get_pwd(input);
            } catch(const std::out_of_range& e) {
                std::cout << "Service not found" << std::endl;
            }
        } else if (input == "gen-passwd") {
            std::cout << Himitsu::Profile::random_passwd();
        }
    }
}

/**
 * Hide or show the user input while typing.
 * @param term The terminal.
 */
static inline int change_visibility(struct termios *term,
                                    int visibility_type)
{
    // Hide user input.
    if (visibility_type == HIDE)
        term->c_lflag &= ~(ECHO);
    else
        term->c_lflag |= ECHO;

    if (tcsetattr(STDIN_FILENO, TCSANOW, 
                  term) == -1) {
        std::cout << "Something went wrong..."
                  << std::endl;
        return -1;
    }

    return 0;
}

static void login(Himitsu::Profile &profile)
{
    std::string username;
    std::string password;
    struct termios terminal;
    
    // Get the username.
    std::cout << "Username: ";
    std::cin  >> username;

    // Prepare for the password.
    std::cout << "Password: ";
    if (tcgetattr(STDIN_FILENO, 
                  &terminal) == -1) {
        std::cout << "Something went wrong..."
                  << std::endl;
        return;
    }

    // Hide input.
    if (change_visibility(&terminal, HIDE) == -1) return;

    // Get the password.
    std::cin >> password;
    std::cout << std::endl;

    // Reset terminal.
    if (change_visibility(&terminal, SHOW) == -1) return; 

    std::cin >> password;
    // TODO - login.
}

int main(int argc, char *argv[])
{
    Himitsu::Profile profile;

    if (argv[1] == NULL) {
        return help();
    } else if (!strcmp(argv[1], "--make-profile")) {
        if (argv[2] == NULL) return help();
        if (argv[3] == NULL) return help();
        if (argv[4] == NULL) return help();
        // Ask for password.

        Himitsu::Profile::mk_new_prof(argv[2], argv[3], argv[4]);
    } else if (!strcmp(argv[1], "--delete-profile")) {
        if (argv[2] == NULL) return help();
        if (argv[3] == NULL) return help();
        if (argv[4] == NULL) return help();
        Himitsu::Profile::del_prof(argv[2], argv[3], argv[3]);
    } else if (!strcmp(argv[1], "--show-profiles")) {
        for (std::string profile 
             : Himitsu::Profile::show_profs()) {
            std::cout << profile << std::endl;
        }
    } else if (!strcmp(argv[1], "--gen-passwd")) {
        std::cout << Himitsu::Profile::random_passwd() << std::endl;
    } else if (!strcmp(argv[1], "--login")) {
        login(profile);
    }
}

#include <cstring>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <sys/mman.h>

#include "profile.h"

// Terminal modes.
#define HIDE 1
#define SHOW 2


#define SMT_WRONG()                         \
    std::cout << "Something went wrong..."  \
              << std::endl;                 \


static int help()
{
    // TODO - help.
    return 0;
}


static int read_sensitive_input(char *dst, size_t max)
{
    char c = '\0';
    size_t i = 0;
    // consume the first character.
    fscanf(stdin, "%c", &c);
    if (c != '\n') {
        dst[0] = c;
        i = 1;
    }

    for (; i < max - 1; i++) {
        fscanf(stdin, "%c", &c);  
        if (feof(stdin) != 0 || c == '\n') break;
        else if (ferror(stdin) != 0) return -1;

        dst[i] = c;
    }
    dst[i] = '\0';

    return 0;
}


static void manager_prompt(Himitsu::Profile &profile, 
                           std::string username)
{
    std::string input;
    // Allocate space for the posible password.
    char *passwd = (char *) OPENSSL_malloc(sizeof(char) * PASSWD_MAX); 

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
        } else if (input == "exit") {
            profile.disconnect();
            std::cout << "Logout..." << std::endl;
            break;
        }
    }

    OPENSSL_free(passwd);
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
        SMT_WRONG();
        return -1;
    }

    return 0;
}

static void login(Himitsu::Profile &profile)
{
    std::string username;
    std::string pname;
    char *password = (char *) OPENSSL_malloc(sizeof(char) * PASSWD_MAX); 
    memset(password, 0x0, PASSWD_MAX);

    int err1, err2, err3 = 0;
    struct termios terminal;
    
    // Get the username.
    std::cout << "Username: ";
    std::cin  >> username;

    // Prepare for the password.
    std::cout << "Password: ";
    if (tcgetattr(STDIN_FILENO, 
                  &terminal) == -1) {
        SMT_WRONG();
        return;
    }

    // Hide input.
    err1 = change_visibility(&terminal, HIDE);

    // Do not allow the password to be written in disk!
    // For security reasons, because it could be restored
    // using foresics methods.
    // Lock Virtual Address page that contains the password
    // in memory.
    if (mlock(password, PASSWD_MAX) != 0) {
        SMT_WRONG();
        OPENSSL_free(password);
        return;
    }

    // Get the password.
    err2 = read_sensitive_input(password, PASSWD_MAX);
    std::cout << std::endl;

    err3 = change_visibility(&terminal, SHOW);
    if (err1 != 0 || err2 != 0 || err3) {
        SMT_WRONG();
        OPENSSL_cleanse(password, PASSWD_MAX);
        OPENSSL_free(password);
        return;
    }    

    // Get profile.
    std::cout << "Profile: ";
    std::cin  >> pname;
    std::cout << std::endl;

    // During connect we change the position of the password
    // in memory, so after that we clean up the local copy.
    profile.connect(username, password, pname);
    // cleanup
    // remove the password from memory.
    OPENSSL_cleanse(password, PASSWD_MAX);

    // unlock address
    if (munlock(password, PASSWD_MAX) != 0) {
        SMT_WRONG();
        OPENSSL_free(password);
    }
    OPENSSL_free(password);

    if (!profile.is_connected()) {
        SMT_WRONG();
        return;
    }

    // If connection is established.
    manager_prompt(profile, username);
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

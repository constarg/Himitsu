#include <cstring>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <sys/mman.h>
#include <malloc.h>


#include "profile.hh"

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

    while(true) {
        fscanf(stdin, "%c", &c);  
        if (feof(stdin) != 0 || c == '\n') break;
        else if (ferror(stdin) != 0) return -1;

        if (i < max) dst[i] = c;
        ++i;
    }
    dst[i] = '\0';

    return 0;
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

/**
 * This functions retrieves the password
 * from the stdin and secure it using mlock.
 * 
 * @return a pointer to the memory address that
 * the password is stored.
 */
static char *ask_for_password()
{
    char *password = (char *) OPENSSL_malloc(sizeof(char) * PASSWD_MAX);
    memset(password, 0x0, PASSWD_MAX);
    struct termios terminal;

    int err1, err2, err3;

    if (tcgetattr(STDIN_FILENO, 
                  &terminal) == -1) {
        SMT_WRONG();
        return nullptr;
    }

    std::cout << "Password: ";

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
        return nullptr;
    }

    // Get the password.
    err2 = read_sensitive_input(password, PASSWD_MAX);
    std::cout << std::endl;

    err3 = change_visibility(&terminal, SHOW);
    if (err1 != 0 || err2 != 0 || err3) {
        SMT_WRONG();
        return nullptr;
    }    

    return password;
}

static int safely_destroy_password(char *password)
{
    // cleanup
    // remove the password from memory.
    OPENSSL_cleanse(password, PASSWD_MAX);

    // unlock address
    if (munlock(password, PASSWD_MAX) != 0) {
        SMT_WRONG();
        OPENSSL_free(password);
        return -1;
    }
    OPENSSL_free(password);

    return 0;
}

static void password_strength(unsigned char *enable_bits, size_t len)
{
    size_t range = 0; // The range of characters.
    
    int entropy;

    range += (LOWER_EN(*enable_bits))?  26 : 0;
    range += (UPPER_EN(*enable_bits))?  26 : 0;
    range += (NUMBER_EN(*enable_bits))? 10 : 0;
    range += (SPECIAL_EN(*enable_bits))? 8 : 0;

    // calculate entropy.
    entropy = Himitsu::Security::password_entropy(len, range);
    if (POOR(entropy)) 
            std::cout << "[!] The password is poor, please make another." 
                      << std::endl;
    else if (WEAK(entropy)) 
            std::cout << "[!] The password is weak, please make another."
                      << std::endl;
    else if (RESONABLE(entropy)) 
            std::cout << "[+] The password is ok but it would be good to make another.";
    else    std::cout << "[*] The password is very good." << std::endl;
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
            //std::cout << Himitsu::Profile::random_passwd();
        } else if (input == "exit") {
            profile.disconnect();
            std::cout << "Logout..." << std::endl;
            break;
        }
    }

    OPENSSL_free(passwd);
}

static void login(Himitsu::Profile &profile)
{
    std::string username;
    std::string pname;
    char *password; 
 
    // Get the username.
    std::cout << "Username: ";
    std::cin  >> username;

    // retrieve the password.
    password = ask_for_password();
    if (!password) return;

    // Get profile.
    std::cout << "Profile: ";
    std::cin  >> pname;
    std::cout << std::endl;

    // During connect we change the position of the password
    // in memory, so after that we clean up the local copy.
    profile.connect(username, password, pname);

    // destory temporary password.
    if (safely_destroy_password(password) != 0) {
        SMT_WRONG();
        return;
    }

    // check if the profile is connected.
    if (!profile.is_connected()) return;
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

        char *passwd = ask_for_password();
        if (!passwd) return 0;
        Himitsu::Profile::mk_new_prof(argv[2], argv[3], passwd);
        if (safely_destroy_password(passwd) != 0) return 0; 
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
        char lower, upper, num, special;
        const char *password;
        size_t len;
        unsigned char enable_bits;
        memset(&enable_bits, 0x0, 1);

        std::cout << "Include lower letters? [Y/n]: ";
        std::cin >> lower;

        std::cout << "Include upper letters? [Y/n]: ";
        std::cin >> upper;

        std::cout << "Include numbers? [Y/n]: ";
        std::cin >> num;

        std::cout << "Include special characters? [Y/n]: ";
        std::cin >> special;

        std::cout << "Password length: ";
        std::cin >> len;
        std::cout << std::endl;

        enable_bits |= (tolower(lower) == 'y')? LOWER_EN_B : 0x00;
        enable_bits |= (tolower(upper) == 'y')? UPPER_EN_B : 0x00;
        enable_bits |= (tolower(num) == 'y')? NUMBER_EN_B : 0x00;
        enable_bits |= (tolower(special) == 'y')? SPECIAL_EN_B : 0x00;

        // Get the requested password.
        password = Himitsu::Profile::random_passwd(len, &enable_bits);
        if (password == NULL) std::cout << "Failed" << std::endl;

        std::cout << password << std::endl;
        GEN_PWD_FREE((void *) password);
        
        std::cout << std::endl << "------Calculate Password Strength------" 
                  << std::endl << std::endl;
        password_strength(&enable_bits, len);

    } else if (!strcmp(argv[1], "--login")) {
        login(profile);
    }
}

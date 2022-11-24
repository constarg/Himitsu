# Himitsu
Himitsu is a terminal-based secure password manager that tries to help you remember your passwords and gives you the functionality to make strong passwords for your online services. 

# Installation requirements
The following packages must be installed.<br>
```
sudo apt-get install build-essential cmake git g++ libssl-dev
```

# Download & Build

First download the program from GitHub and go to the Himitsu folder.

```
% git clone https://github.com/EmbeddedCat/Himitsu.git
% cd Himitsu/
```

After installation the program must be built. In order to build the program, the following instructions must be
followed.<br>

```
% make
% make install
```

After this the program will be installed and ready to run.

# Technical details

**Himitsu** stores records and each record contains two pieces of information, the first one is the username, and the second is the password. The username and the password are securely encrypted using the **AES** algorithm, which applies to each record.<br>
Each record represents a service you want to keep, for example, if you wanted to keep the credentials for your Facebook account, this is a record.<br>
To access those records (a.k.a accounts) you must log in to your profile first. Himitsu allows you to create an infinite number of profiles, but for practical reasons, I suggest using one. To log in to your profile, you must enter a username and a password. Later this password is used to encrypt your data.<br>
For a specific profile, let's say myprofile, the username and the password are stored as SHA256 representation locally in **~/.local/Himitsu/logins/myprofile**. To successfully log in, the **SHA256** Hash of the username and the **SHA256** Hash of the password must be equal to the hashes in the login file.<br>
After successful login, **Himitsu** retrieves all the records from the file that represents the current login profile and stores them in the memory. Each record that is stored in memory is still encrypted! no decryption has yet taken place. If you request for the username and password, let's say Facebook, only then does the Himitsu decrypt, using the password used to log in, this and only this specific record.<br>
Because the password used to log in must always remain in memory, **Himitsu** encrypts this password using data from an **OpenSSL** random function as the secret key. **Himitsu** decrypts the password only when there is a request for a record.<br><br>
That's it!!!, I hope you like my password manager, any contributions are welcomed.

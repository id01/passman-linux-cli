## Password Manager
C++ Linux Command Line Interface Submodule  

## Description
This is a (no longer so) simple password manager that runs on mySQL.  
This is the webextension submodule.  

## C++ Interface Installation
Download libscrypt from [here](https://github.com/technion/libscrypt) and build it.  
Copy libscrypt.a and libscrypt.h to libscrypt.  
Change the serverURL variable in main/config.h to your server URL.  
Run linux_cli/build.sh.  

## Dependencies
* CryptoPP  
* openssl  
* libcurl  
* lpthread  
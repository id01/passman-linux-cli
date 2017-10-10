## Password Manager
C++ Linux Command Line Interface Submodule  

## Description
This is a (no longer so) simple password manager that runs on mySQL.  
This is the webextension submodule.  

## C++ Interface Installation
Download scrypt-jane and move it to scrypt-jane/. Build it using 'gcc scrypt-jane.c -O3 -DSCRYPT_SALSA -DSCRYPT_SHA256 -c'.  
Change the serverURL variable in main/config.h to your server URL.  
Run linux_cli/build.sh.  

## Dependencies
* CryptoPP  
* Scrypt-Jane  
* openssl  
* libcurl  
* lpthread  
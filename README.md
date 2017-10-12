## Password Manager
C++ Windows GUI Interface Submodule  

## Description
This is a (no longer so) simple password manager that runs on mySQL.  
This is the webextension submodule.  

## C++ Interface Installation
Download scrypt-jane, copy it to scrypt-jane/, and build it with -c -DSCRYPT_SALSA -DSCRYPT_SHA256.  
Change the serverURL variable in main/config.h to your server URL.  
Run linux_cli/build.sh.  

## Building Dependencies
* CryptoPP  
* Scrypt-jane  
* openssl  
* libcurl  
* lpthread  

## Runtime Dependencies
None

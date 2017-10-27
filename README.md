## Password Manager
C++ Linux Command Line Interface Submodule  

## Description
This is a (no longer so) simple password manager that runs on SQLAlchemy.  
This is the Linux CLI submodule.  

## C++ Interface Installation
Download scrypt-jane and move it to scrypt-jane/. Build it using 'gcc scrypt-jane.c -O3 -DSCRYPT_SALSA -DSCRYPT_SHA256 -c'.  
Copy linux_cli/config_example.h to linux_cli/config.h.
Change the serverURL variable in linux_cli/config.h to your server URL.  
Run linux_cli/build.sh.  

## Dependencies
* CryptoPP  
* Scrypt-Jane  
* openssl  
* libcurl  
* lpthread  

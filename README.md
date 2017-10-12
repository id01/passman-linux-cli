## Password Manager
C++ Windows GUI Interface Submodule  

## Description
This is a (no longer so) simple password manager that runs on mySQL.  
This is the webextension submodule.  

<<<<<<< HEAD
## Windows Interface Installation
Building is split into 2 parts - MinGW for C++ building of Backend (not usable) and Visual C# for GUI wrapper.  
#### Step 1: MinGW Building (Backend)
Download cryptopp 5.6.5 to cryptopp/.  
Apply [patch](https://github.com/weidai11/cryptopp/commit/51d3cc945fe388c776a1a20683ba8ff1c2f191e2).  
Apply [patch](https://github.com/DragonFlyBSD/DPorts/issues/79).  
Download scrypt-jane and move it to scrypt-jane/.  
Note: Remove x86_64-w64-mingw32 if on Windows.  
Build dependencies, then project:  
```
cd cryptopp  
make CXX=x86_64-w64-mingw32-g++ CC=x86_64-w64-mingw32-gcc  
cd ../scrypt-jane  
x86_64-w64-mingw32-gcc scrypt-jane.c -O3 -DSCRYPT_SALSA -DSCRYPT_SHA256 -c  
cd ../main
x86_64-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ main.cpp ../scrypt-jane/scrypt-jane.o -L../cryptopp -lcryptopp -O2 -shared -o main.dll  
```
=======
## C++ Interface Installation
Download libscrypt from [here](https://github.com/technion/libscrypt) and build it.  
Copy libscrypt.a and libscrypt.h to libscrypt.  
>>>>>>> parent of 1aa6ea5... 	modified:   .gitignore
Change the serverURL variable in main/config.h to your server URL.  
Run linux_cli/build.sh.  
#### Step 2: Visual C# Building (C# GUI)
Finish building Backend  
Open C# project in windows_gui/ in Visual Studio  
Build  
Copy main.dll to output directory where the final, built exe is  
Run  

## Building Dependencies
* CryptoPP  
<<<<<<< HEAD
* Scrypt-jane  
* Visual Studio  

## Runtime Dependencies
None
=======
* openssl  
* libcurl  
* lpthread  
>>>>>>> parent of 1aa6ea5... 	modified:   .gitignore

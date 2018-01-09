## Password Manager
C++ Windows GUI/Linux Command Line Interface Submodule  
Latest Version: 1.0.2

## Description
This is a (no longer so) simple password manager that runs on SQLAlchemy.  
This is the C++ interface submodule.  

## Linux CLI Installation
Download scrypt-jane and move it to scrypt-jane/. Build it using `gcc scrypt-jane.c -O3 -DSCRYPT_SALSA -DSCRYPT_SHA256 -c`.  
Copy linux_cli/config_example.h to linux_cli/config.h.  
Change the serverURL variable in linux_cli/config.h to your server URL.  
Run linux_cli/build.sh. This should generate a binary called cli.  

## Windows Interface Installation
Building is split into 2 parts - MinGW for C++ building of Backend (a DLL) and Visual C# for GUI wrapper (an executable).  
#### Step 1: MinGW Building (Backend)
Download cryptopp 5.6.5 to cryptopp/.  
Apply [patch](https://github.com/weidai11/cryptopp/commit/51d3cc945fe388c776a1a20683ba8ff1c2f191e2).  
Apply [patch](https://github.com/DragonFlyBSD/DPorts/issues/79).  
Download scrypt-jane and move it to scrypt-jane/.  
Note: Remove x86_64-w64-mingw32 if on Windows.  
Build dependencies, then project:  
```
cd cryptopp  
make CXX=x86_64-w64-mingw32-g++ CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar RANLIB=x86_64-w64-mingw32-ranlib  
cd ../scrypt-jane  
x86_64-w64-mingw32-gcc scrypt-jane.c -O3 -DSCRYPT_SALSA -DSCRYPT_SHA256 -c  
cd ../main
x86_64-w64-mingw32-g++ -static windows.cpp ../scrypt-jane/scrypt-jane.o -I.. -L../cryptopp -lcryptopp -O2 -shared -o windows.dll  
```
#### Step 2: Visual C# Building (C# GUI)
Finish building Backend  
Open C# project in windows_gui/ in Visual Studio  
Build  
Copy windows.dll to output directory where the final, built exe is  
Run  

## Dependencies
* CryptoPP  
* Scrypt-jane  
* OpenSSL+libcURL  
* (For building Windows GUI only) Visual Studio  
Note: Dependencies are only required at runtime on Linux if not statically linked. On Windows, the binary should be statically linked and therefore no dependencies should be required.  
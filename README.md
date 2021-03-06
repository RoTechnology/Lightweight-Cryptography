# Lightweight-Cryptography
## Overview
The LCM (Lightweigth Cryptography Module) is a software component proposed to improve network performance through the implementation of a Cryptographic Scheme with Cryptography and Intrusion Detection functionalities.
The LCM is actually built for a specific [Comp4Drones](https://www.comp4drones.eu) Reactive Security case study.
## How it works
The  component offers its security features for communications between different entities by encrypting and decrypting the data that is be exchanged between them.
Moreover, when an encrypted data is received, the component verifies the authenticity of the message.
## Files description
The *LCM.h* file implements all the main functions of the cryptographic module.

The *TAKS.h* is the library that implements the TAKS algorithm.

The *AES.h* is the library that implements the symmetric message encryption and decryption functions.
## Usage description
To correctly use the library tests follow this steps:

1.  Include .h files into the project folder
2.  Compile main.c and run your code 

**Make sure to include the right files based on the OS used.**

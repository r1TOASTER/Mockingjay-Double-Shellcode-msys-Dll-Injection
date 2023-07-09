# Mockingjay-Double-Shellcode-msys-Injection

This project demonstrates a DLL injector written in C++ that injects a reverse shell and an injector shell written in assembly language. The reverse shell connects to a specified listening host and port (which can be modified in the code). The injector shell obtains the necessary functions (e.g., WriteProcessMemory) to inject code, specifically the reverse shell, into the svchost process and executes it. The msys DLL injector takes the complete shellcode, including the injector shellcode containing the reverse shell, locates the Read-Write-Execute (RWX) section of the msys DLL (in order to take advantage of the free RWX pages inside it), moves the shellcode to that section, and executes it.

## Prerequisites
This project is intended for educational purposes only.
The code and DLLs are designed for x86 architecture. Please ensure that you compile and run them accordingly.

## Usage
To use this project, please follow these steps:

- Compile each file in x86 mode using an appropriate compiler, such as Visual Studio or GCC. Ensure that you compile them with the necessary flags to target the x86 architecture.
- Place the compiled reverse shell executable inside the shell injector code (in the labels below).
- Compile the shell injector, including the reverse shell, and put it into the msys DLL injector. Ensure that you compile the msys DLL injector with the necessary flags to target the x86 architecture.
- Run the compiled msys DLL injector executable, after the host IP is listening for connection.
- Please note that the project should be used for educational purposes only. Usage of this project for any illegal or malicious activities is strictly prohibited. The code and resulting binaries should be used responsibly and in compliance with applicable laws and regulations.

## Project Structure
MsysInjector.cpp: Contains the C++ DLL injector code.
InjectorShell.asm: Contains the assembly code for the injector shell.
ReverseShell.asm: Contains the code for the reverse shell.

## Instructions
- Modify the desired settings, such as the listening host and port, within the code files.
- Build the project accordingly to the **Usage**.
Please note that the project should be used for educational purposes only. Usage of this project for any illegal or malicious activities is strictly prohibited. The code and resulting binaries should be used responsibly and in compliance with applicable laws and regulations.

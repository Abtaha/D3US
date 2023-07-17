#include <stdio.h>
#include <string>

#include "Utils.h"

void Logging::INFO(std::string msg) {
    printf("[+] %s\n", msg.c_str());
}

void Logging::INFO(std::wstring msg) {
    printf("[+] %ls\n", msg.c_str());
}

void Logging::WARNING(std::string msg) {
    printf("[-] %s\n", msg.c_str());
}

void Logging::WARNING(std::wstring msg) {
    printf("[-] %ls\n", msg.c_str());
}

void Logging::ERR(std::string msg) {
    printf("[!] %s\n", msg.c_str());
}

void Logging::ERR(std::wstring msg) {
    printf("[!] %ls\n", msg.c_str());
}

void Logging::END() {
    printf("\n");
}

std::string deobfuscateString(std::string obsFuncName) {
    std::string funcName = "";

    for (size_t i = 0; i < obsFuncName.size(); i++) {
        int curr_char = obsFuncName[i];

        bool caps = false;
        if (curr_char >= 97 && curr_char <= 122) {
            curr_char -= 97;
            caps = false;
        } else if (curr_char >= 65 && curr_char <= 90) {
            curr_char -= 65;
            caps = true;
        } else {
            funcName += curr_char;
            continue;
        }

        curr_char -= 13;

        if (curr_char < 0)
            curr_char = curr_char + 26;

        if (caps)
            curr_char += 65;
        else
            curr_char += 97;

        funcName += curr_char;
    }

    return funcName;
}
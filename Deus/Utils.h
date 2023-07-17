#pragma once

#include <stdio.h>
#include <string>

std::string deobfuscateString(std::string obsFuncName);

namespace Logging {
void INFO(std::string msg);
void INFO(std::wstring msg);

void WARNING(std::string msg);
void WARNING(std::wstring msg);

void ERR(std::string msg);
void ERR(std::wstring msg);

void END();
}  // namespace Logging

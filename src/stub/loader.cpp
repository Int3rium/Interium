#include <windows.h>
#include <string.h>
#include "loader.h"
// #include <stdio.h> // debug

namespace Loader {

typedef struct {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sections;
} PE_HEADERS;

static bool parseHeaders(const u8* data, size_t size, PE_HEADERS* h) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return false;

    h->dos = (PIMAGE_DOS_HEADER)data;
    if (h->dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if ((DWORD)h->dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size) return false;

    h->nt = (PIMAGE_NT_HEADERS)(data + h->dos->e_lfanew);
    if (h->nt->Signature != IMAGE_NT_SIGNATURE) return false;

    h->sections = IMAGE_FIRST_SECTION(h->nt);
    return true;
}

static void processRelocations(void* base, PE_HEADERS* h, DWORD_PTR delta) {
    PIMAGE_DATA_DIRECTORY relocDir = &h->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->Size == 0) return;

    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((u8*)base + relocDir->VirtualAddress);

    while (reloc->VirtualAddress && reloc->SizeOfBlock) {
        u8* relocBase = (u8*)base + reloc->VirtualAddress;
        WORD* entries = (WORD*)(reloc + 1);
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (DWORD i = 0; i < count; i++) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* addr = (DWORD*)(relocBase + offset);
                *addr += (DWORD)delta;
            }
#ifdef _WIN64
            else if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* addr = (ULONGLONG*)(relocBase + offset);
                *addr += delta;
            }
#endif
        }

        reloc = (PIMAGE_BASE_RELOCATION)((u8*)reloc + reloc->SizeOfBlock);
    }
}

static bool resolveImports(void* base, PE_HEADERS* h) {
    PIMAGE_DATA_DIRECTORY importDir = &h->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0) return true;

    PIMAGE_IMPORT_DESCRIPTOR imports = (PIMAGE_IMPORT_DESCRIPTOR)((u8*)base + importDir->VirtualAddress);

    while (imports->Name) {
        const char* dllName = (const char*)((u8*)base + imports->Name);
        HMODULE hDll = LoadLibraryA(dllName);
        if (!hDll) { // TODO: handle delay-loaded DLLs properly
            imports++;
            continue;
        }

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((u8*)base + imports->FirstThunk);
        PIMAGE_THUNK_DATA origThunk = imports->OriginalFirstThunk ?
            (PIMAGE_THUNK_DATA)((u8*)base + imports->OriginalFirstThunk) : thunk;

        while (origThunk->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                thunk->u1.Function = (ULONG_PTR)GetProcAddress(hDll,
                    MAKEINTRESOURCEA(IMAGE_ORDINAL(origThunk->u1.Ordinal)));
            } else {
                PIMAGE_IMPORT_BY_NAME imp = (PIMAGE_IMPORT_BY_NAME)((u8*)base + origThunk->u1.AddressOfData);
                thunk->u1.Function = (ULONG_PTR)GetProcAddress(hDll, imp->Name);
            }
            thunk++;
            origThunk++;
        }
        imports++;
    }
    return true;
}

static void fixSectionPermissions(void* base, PE_HEADERS* h) {
    for (WORD i = 0; i < h->nt->f_Header.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sec = &h->sections[i];
        void* addr = (u8*)base + sec->VirtualAddress;
        SIZE_T size = sec->Misc.VirtualSize;
        if (size == 0) continue;

        DWORD protect = PAGE_READONLY;
        DWORD chars = sec->Characteristics;

        if ((chars & IMAGE_SCN_MEM_EXECUTE) && (chars & IMAGE_SCN_MEM_WRITE))
            protect = PAGE_EXECUTE_READWRITE;
        else if (chars & IMAGE_SCN_MEM_EXECUTE)
            protect = PAGE_EXECUTE_READ;
        else if (chars & IMAGE_SCN_MEM_WRITE)
            protect = PAGE_READWRITE;

        DWORD old;
        VirtualProtect(addr, size, protect, &old);
    }
}

void* m_Map(const u8* peData, size_t size) {
    PE_HEADERS h;
    if (!parseHeaders(peData, size, &h)) return NULL;
    SIZE_T imageSize = h.nt->OptionalHeader.SizeOfImage;

    void* base = VirtualAlloc( // try preferred base first
        (void*)(ULONG_PTR)h.nt->OptionalHeader.ImageBase,
        imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!base) {
        base = VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    if (!base) return NULL;

    memset(base, 0, imageSize);
    memcpy(base, peData, h.nt->OptionalHeader.SizeOfHeaders);

    for (WORD i = 0; i < h.nt->f_Header.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sec = &h.sections[i];
        if (sec->SizeOfRawData > 0 && sec->PointerToRawData > 0) {
            memcpy((u8*)base + sec->VirtualAddress,
                   peData + sec->PointerToRawData,
                   sec->SizeOfRawData);
        }
    }

    parseHeaders((const u8*)base, imageSize, &h);
    DWORD_PTR delta = (DWORD_PTR)base - h.nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        processRelocations(base, &h, delta);
    }

    resolveImports(base, &h);
    fixSectionPermissions(base, &h);

    PIMAGE_DATA_DIRECTORY tlsDir = &h.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir->Size > 0) {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)((u8*)base + tlsDir->VirtualAddress);
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (callbacks) {
            while (*callbacks) {
                (*callbacks)(base, DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }

    return base;
}

bool e_InMem(const u8* peData, size_t size) {
    PE_HEADERS h;
    if (!parseHeaders(peData, size, &h)) return false;

    void* mapped = m_Map(peData, size);
    if (!mapped) return false;

    parseHeaders((const u8*)mapped, h.nt->OptionalHeader.SizeOfImage, &h);

    DWORD entryRVA = h.nt->OptionalHeader.AddressOfEntryPoint;
    if (entryRVA == 0) return false;
    void* entryPoint = (u8*)mapped + entryRVA;

    if (h.nt->f_Header.Characteristics & IMAGE_FILE_DLL) {
        typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
        DllMain_t dllMain = (DllMain_t)entryPoint;
        dllMain((HINSTANCE)mapped, DLL_PROCESS_ATTACH, NULL);
    } else {
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    }

    return true;
}
}

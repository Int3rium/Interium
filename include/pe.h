#ifndef INTERIUM_PE_H
#define INTERIUM_PE_H

#include "types.h"
#include <vector>
#include <string>

namespace Interium {

// PE structures
#pragma pack(push, 1)

struct DOS_HEADER {
    u16 e_magic;
    u16 e_cblp;
    u16 e_cp;
    u16 e_crlc;
    u16 e_cparhdr;
    u16 e_minalloc;
    u16 e_maxalloc;
    u16 e_ss;
    u16 e_sp;
    u16 e_csum;
    u16 e_ip;
    u16 e_cs;
    u16 e_lfarlc;
    u16 e_ovno;
    u16 e_res[4];
    u16 e_oemid;
    u16 e_oeminfo;
    u16 e_res2[10];
    i32 e_lfanew;
};

struct FILE_HEADER {
    u16 Machine;
    u16 NumberOfSections;
    u32 TimeDateStamp;
    u32 PointerToSymbolTable;
    u32 NumberOfSymbols;
    u16 SizeOfOptionalHeader;
    u16 Characteristics;
};

struct DATA_DIRECTORY {
    u32 VirtualAddress;
    u32 Size;
};

struct OPTIONAL_HEADER_64 {
    u16 Magic;
    u8  MajorLinkerVersion;
    u8  MinorLinkerVersion;
    u32 SizeOfCode;
    u32 SizeOfInitializedData;
    u32 SizeOfUninitializedData;
    u32 AddressOfEntryPoint;
    u32 BaseOfCode;
    u64 ImageBase;
    u32 SectionAlignment;
    u32 FileAlignment;
    u16 MajorOperatingSystemVersion;
    u16 MinorOperatingSystemVersion;
    u16 MajorImageVersion;
    u16 MinorImageVersion;
    u16 MajorSubsystemVersion;
    u16 MinorSubsystemVersion;
    u32 Win32VersionValue;
    u32 SizeOfImage;
    u32 SizeOfHeaders;
    u32 CheckSum;
    u16 Subsystem;
    u16 DllCharacteristics;
    u64 SizeOfStackReserve;
    u64 SizeOfStackCommit;
    u64 SizeOfHeapReserve;
    u64 SizeOfHeapCommit;
    u32 LoaderFlags;
    u32 NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
};

struct OPTIONAL_HEADER_32 {
    u16 Magic;
    u8  MajorLinkerVersion;
    u8  MinorLinkerVersion;
    u32 SizeOfCode;
    u32 SizeOfInitializedData;
    u32 SizeOfUninitializedData;
    u32 AddressOfEntryPoint;
    u32 BaseOfCode;
    u32 BaseOfData;
    u32 ImageBase;
    u32 SectionAlignment;
    u32 FileAlignment;
    u16 MajorOperatingSystemVersion;
    u16 MinorOperatingSystemVersion;
    u16 MajorImageVersion;
    u16 MinorImageVersion;
    u16 MajorSubsystemVersion;
    u16 MinorSubsystemVersion;
    u32 Win32VersionValue;
    u32 SizeOfImage;
    u32 SizeOfHeaders;
    u32 CheckSum;
    u16 Subsystem;
    u16 DllCharacteristics;
    u32 SizeOfStackReserve;
    u32 SizeOfStackCommit;
    u32 SizeOfHeapReserve;
    u32 SizeOfHeapCommit;
    u32 LoaderFlags;
    u32 NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];
};

struct NT_HEADERS_64 {
    u32 Signature;
    FILE_HEADER f_Header;
    OPTIONAL_HEADER_64 OptionalHeader;
};

struct NT_HEADERS_32 {
    u32 Signature;
    FILE_HEADER f_Header;
    OPTIONAL_HEADER_32 OptionalHeader;
};

struct SECTION_HEADER {
    u8  Name[8];
    u32 VirtualSize;
    u32 VirtualAddress;
    u32 SizeOfRawData;
    u32 PointerToRawData;
    u32 PointerToRelocations;
    u32 PointerToLinenumbers;
    u16 NumberOfRelocations;
    u16 NumberOfLinenumbers;
    u32 Characteristics;
};

struct IMPORT_DESCRIPTOR {
    u32 OriginalFirstThunk;
    u32 TimeDateStamp;
    u32 ForwarderChain;
    u32 Name;
    u32 FirstThunk;
};

struct RICH_ENTRY {
    u16 buildId;
    u16 prodId;
    u32 count;
};
#pragma pack(pop)

// DataDirectory indices we actually use
enum {
    DIR_EXPORT = 0,
    DIR_IMPORT = 1,
    DIR_RESOURCE = 2,
    DIR_EXCEPTION = 3,
    DIR_SECURITY = 4,
    DIR_BASERELOC = 5,
    DIR_DEBUG = 6,
    DIR_TLS = 9,
    DIR_LOAD_CONFIG = 10,
    DIR_BOUND_IMPORT = 11,
    DIR_IAT = 12,
    DIR_DELAY_IMPORT = 13,
    DIR_CLR = 14
};

class PEFile {
public:
    bool load(const std::string& path);
    bool save(const std::string& path);

    bool is64bit() const { return is64; }

    std::vector<u8>& data() { return raw; }
    const std::vector<u8>& data() const { return raw; }

    DOS_HEADER* d_Header();
    NT_HEADERS_64* ntHeaders64();
    NT_HEADERS_32* ntHeaders32();
    FILE_HEADER* f_Header();
    SECTION_HEADER* s_Headers();
    u16 s_Count() const;
    u32 entryPoint() const;

    SECTION_HEADER* findSection(const std::string& name);
    SECTION_HEADER* sectionFromRva(u32 rva);
    u32 rvaToOffset(u32 rva);
    u32 offsetToRva(u32 offset);

    SECTION_HEADER* addSection(const std::string& name, u32 size, u32 characteristics);

    bool hasRichHeader() const;
    size_t richHeaderOffset() const;
    size_t richHeaderSize() const;

private:
    std::vector<u8> raw;
    bool is64 = false;
};

} // namespace Interium

#endif

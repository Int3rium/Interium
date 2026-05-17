#ifndef INTERIUM_STUB_H
#define INTERIUM_STUB_H

#include "types.h"

#pragma pack(push, 1)
struct StubConfig {
    u32 magic; // 'ITRM' searched for from EOF backwards
    u32 payloadSize;
    u32 keySize;
    u8  level;
    u8  flags;
    u8  reserved[2];
    // followed by: key[keySize] then ePayload[payloadSize]
};
#pragma pack(pop)

#define STUB_MAGIC 0x4D525449  // 'ITRM'

#define FLAG_ANTI_VM     0x01
#define FLAG_ANTI_DEBUG  0x02
#define FLAG_DELAY_EXEC  0x04
#define FLAG_SELF_DELETE 0x08

#endif

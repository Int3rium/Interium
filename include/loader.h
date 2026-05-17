#ifndef INTERIUM_LOADER_H
#define INTERIUM_LOADER_H

#include "types.h"

namespace Loader {

bool e_InMem(const u8* peData, size_t size);
void* m_Map(const u8* peData, size_t size);

}

#endif

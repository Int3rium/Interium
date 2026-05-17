#ifndef INTERIUM_TRANSFORMS_H
#define INTERIUM_TRANSFORMS_H

#include "pe.h"
#include <string>
#include <vector>

namespace Interium {

enum class Level { LOW, MID, HIGH };

struct Stats {
    int importsHidden = 0;
    int sectionsRenamed = 0;
    int metadataCleaned = 0;
    int junkBytesAdded = 0;
};

void cleanMetadata(PEFile& pe, Stats& stats);
void cleanRichHeader(PEFile& pe, Stats& stats);
void killDosStub(PEFile& pe, Stats& stats);
void renameSections(PEFile& pe, Stats& stats);
void spoofPECharacteristics(PEFile& pe, Stats& stats);
void shuffleImports(PEFile& pe, Stats& stats);
void addOverlay(PEFile& pe, Level level, Stats& stats);
void fixChecksum(PEFile& pe);

} // namespace Interium

#endif

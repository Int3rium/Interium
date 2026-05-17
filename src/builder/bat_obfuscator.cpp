#include "bat_obfuscator.h"
#include <random>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace Interium {

static std::mt19937& rng() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    return gen;
}

static int randInt(int lo, int hi) {
    return std::uniform_int_distribution<int>(lo, hi)(rng());
}

static char randAlpha() {
    const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    return chars[randInt(0, 51)];
}

static std::string randAlphaNum(int len) {
    const char* chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    result.reserve(len);
    for (int i = 0; i < len; i++) {
        result += chars[randInt(0, 61)];
    }
    return result;
}

BatObfuscator::BatObfuscator(Level lvl) : level_(lvl) {}

std::string BatObfuscator::r_Var(int minLen, int maxLen) {
    int len = randInt(minLen, maxLen);
    std::string var;
    var += randAlpha(); // must start with letter
    for (int i = 1; i < len; i++) {
        var += randAlphaNum(1)[0];
    }
    varCounter_++;
    return var;
}

BatObfuscator::AtomizedString BatObfuscator::a_Str(const std::string& str) {
    AtomizedString result;
    std::ostringstream decl;
    std::string resultExpr = "";

    if (level_ == Level::LOW) {
        // LOW: just put it in one variable
        std::string v = r_Var();
        decl << "set \"" << v << "=" << str << "\"\n";
        result.declarations = decl.str();
        result.resultVar = "%" + v + "%";
        return result;
    }

    // MID/HIGH: split each character into its own variable
    std::vector<std::string> charVars;
    for (char c : str) {
        std::string v = r_Var(4, 8);
        decl << "set \"" << v << "=" << c << "\"\n";
        charVars.push_back(v);
    }

    std::ostringstream expr;
    for (const auto& cv : charVars) {
        expr << "%" << cv << "%";
    }

    std::string concatVar = r_Var();
    decl << "set \"" << concatVar << "=" << expr.str() << "\"\n";

    result.declarations = decl.str();
    result.resultVar = "%" + concatVar + "%";
    return result;
}

std::string BatObfuscator::g_JunkLines(int count) {
    std::ostringstream out;

    // templates that do nothing but look like real batch logic to casual readers
    static const char* junkTemplates[] = {
        ":: %s",
        "REM %s",
        "if 1==0 (echo %s >nul 2>&1)",
        "set \"%s=%s\" >nul 2>&1",
        "if defined %s (set \"%s=\") >nul 2>&1",
        "for %%%%a in () do @echo %%%%a >nul 2>&1", // empty set = never executes
    };

    for (int i = 0; i < count; i++) {
        int tmpl = randInt(0, 4);
        std::string r1 = randAlphaNum(randInt(8, 24));
        std::string r2 = randAlphaNum(randInt(6, 16));

        switch (tmpl) {
            case 0:
                out << ":: " << r1 << "\n";
                break;
            case 1:
                out << "REM " << r1 << "\n";
                break;
            case 2:
                out << "if 1==0 (echo " << r1 << " >nul 2>&1)\n";
                break;
            case 3:
                out << "set \"" << r_Var(4, 6) << "=" << r2 << "\" >nul 2>&1\n";
                break;
            case 4:
                out << "if defined " << r_Var(4,6) << " (set \"" << r_Var(4,6) << "=\") >nul 2>&1\n";
                break;
        }
    }
    return out.str();
}

std::string BatObfuscator::g_Spaghetti(const std::string& realLabel, int fakeCount) {
    std::ostringstream out;
    std::vector<std::string> fakeLabels;
    for (int i = 0; i < fakeCount; i++) {
        fakeLabels.push_back("L_" + randAlphaNum(8));
    }
    out << "goto " << realLabel << "\n";

    for (const auto& fl : fakeLabels) {
        out << ":" << fl << "\n";
        out << g_JunkLines(randInt(2, 5));
        if (randInt(0, 1)) {
            int target = randInt(0, (int)fakeLabels.size() - 1);
            out << "goto " << fakeLabels[target] << "\n";
        } else {
            out << "goto " << realLabel << "\n";
        }
    }

    out << ":" << realLabel << "\n";
    return out.str();
}

std::string BatObfuscator::i_JunkComments(const std::string& script) {
    std::istringstream stream(script);
    std::ostringstream out;
    std::string line;
    int lineCount = 0;

    while (std::getline(stream, line)) {
        out << line << "\n";
        lineCount++;
        int freq = (level_ == Level::HIGH) ? 2 : (level_ == Level::MID) ? 3 : 5;
        if (lineCount % freq == 0) {
            int junkCount = (level_ == Level::HIGH) ? randInt(2, 4) : randInt(1, 2);
            out << g_JunkLines(junkCount);
        }
    }
    return out.str();
}

std::string BatObfuscator::a_Spaghetti(const std::string& script) {
    if (level_ < Level::HIGH) return script;

    std::ostringstream out;
    std::istringstream stream(script);
    std::string line;
    int sectionIdx = 0;

    std::vector<std::string> lines;
    while (std::getline(stream, line)) {
        lines.push_back(line);
    }

    size_t chunkSize = std::max((size_t)8, lines.size() / 6);
    size_t i = 0;
    std::string prevLabel;

    while (i < lines.size()) {
        std::string label = "S_" + randAlphaNum(6) + "_" + std::to_string(sectionIdx);

        if (sectionIdx > 0) {
            out << g_Spaghetti(label, randInt(2, 4));
        } else {
            out << ":" << label << "\n";
        }

        size_t end = std::min(i + chunkSize, lines.size());
        for (size_t j = i; j < end; j++) {
            out << lines[j] << "\n";
        }

        prevLabel = label;
        i = end;
        sectionIdx++;
    }

    return out.str();
}

std::string BatObfuscator::obfuscate(const std::string& script) {
    std::string result = script;

    result = i_JunkComments(result);
    result = a_Spaghetti(result);

    return result;
}

}

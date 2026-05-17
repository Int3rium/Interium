#ifndef INTERIUM_BAT_OBFUSCATOR_H
#define INTERIUM_BAT_OBFUSCATOR_H

#include <string>
#include <vector>
#include "transforms.h"

namespace Interium {

class BatObfuscator {
public:
    explicit BatObfuscator(Level level);

    std::string obfuscate(const std::string& script);
    std::string r_Var(int minLen = 6, int maxLen = 12);

    struct AtomizedString {
        std::string declarations;
        std::string resultVar;
    };
    AtomizedString a_Str(const std::string& str);

    std::string g_JunkLines(int count);
    std::string g_Spaghetti(const std::string& realLabel, int fakeCount);

private:
    Level level_;
    int varCounter_ = 0;

    std::string r_Vars(const std::string& script);
    std::string i_JunkComments(const std::string& script);
    std::string a_Spaghetti(const std::string& script);
};

} // namespace Interium

#endif

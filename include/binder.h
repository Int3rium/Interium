#ifndef INTERIUM_BINDER_H
#define INTERIUM_BINDER_H

#include <string>
#include <vector>
#include <cstdint>
#include "transforms.h"

namespace Interium {

struct BinderConfig {
    std::string i_Exe;
    std::string o_Cmd;
    Level peLevel;
    Level batLevel;
    bool s_Del;
    bool h_Exec;
    bool a_PeObf;
};

bool g_Cmd(const BinderConfig& cfg);

} // namespace Interium

#endif

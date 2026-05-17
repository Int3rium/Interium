#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building Interium Crypter..."

mkdir -p build
cd build

echo "Configuring builder..."
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

echo "Builder compiled: build/interium"

if command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "Cross-compiling stub for Windows..."
    mkdir -p stub
    cd stub
    cmake ../.. -DBUILD_STUB=ON \
        -DCMAKE_SYSTEM_NAME=Windows \
        -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
        -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++
    make -j$(nproc)
    echo "Stub compiled: build/stub/stub.exe"
else
    echo "mingw-w64 not found, skipping stub compilation"
    echo "    Install with: sudo apt install mingw-w64"
fi

echo ""
echo "Build complete!"
echo ""
echo "Usage: ./build/interium --file <exe> --level mid"

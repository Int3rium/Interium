$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Building Interium Crypter (Windows/MSVC)..."

New-Item -ItemType Directory -Force -Path build | Out-Null
Push-Location build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
Pop-Location

Write-Host "Builder compiled: build\Release\interium.exe"

New-Item -ItemType Directory -Force -Path build-stub | Out-Null
Push-Location build-stub
cmake .. -DBUILD_STUB=ON -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
Pop-Location

Write-Host "Stub compiled: build-stub\Release\stub.exe"
Write-Host ""
Write-Host "Build complete UwU"
Write-Host ""
Write-Host "Usage: .\build\Release\interium.exe --file payload.exe --level mid"

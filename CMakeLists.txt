cmake_minimum_required(VERSION 3.20)
project(ghost LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Build configuration
# ---------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Static CRT — no runtime DLL dependencies
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Compiler flags
set(CMAKE_CXX_FLAGS "/W4 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /EHsc")
set(CMAKE_CXX_FLAGS_RELEASE "/O2 /GL /GS-")
set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi /DDEBUG")

# Linker flags — release uses LTCG and strips relocs
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG /OPT:REF /OPT:ICF")

# ---------------------------------------------------------------------------
# Executable
# ---------------------------------------------------------------------------

add_executable(ghost WIN32
    src/main.cpp
    src/syscalls.cpp
    src/evasion.cpp
    src/injection.cpp
    src/persistence.cpp
    src/c2.cpp
    src/utils.cpp
    resources/ghost.rc
)

target_include_directories(ghost PRIVATE include)

target_link_libraries(ghost PRIVATE
    winhttp
    wbemuuid
    ole32
    oleaut32
    ntdll
    advapi32
    shell32
    user32
)

# ---------------------------------------------------------------------------
# Install (optional — copies binary to project root)
# ---------------------------------------------------------------------------

install(TARGETS ghost RUNTIME DESTINATION ${CMAKE_SOURCE_DIR}/dist)
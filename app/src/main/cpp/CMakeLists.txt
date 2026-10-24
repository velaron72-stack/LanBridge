cmake_minimum_required(VERSION 3.22.1)
project(lanbridge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LB_CORE_SOURCES
    jni_bridge.cpp
    addr.cpp
    engine.cpp
    engine_group.cpp
    engine_net.cpp
    engine_tun.cpp
    group.cpp
    crypto.cpp
    frag.cpp
    ipv6.cpp
    offer.cpp
    plat.cpp
    protocol.cpp
    stun.cpp
    udpio.cpp
    util.cpp)

if(WIN32)
    # Windows (desktop build, cross-compiled with llvm-mingw or built with MinGW): lanbridge.dll for the JVM.
    # JNI headers: JAVA_HOME/include (portable jni.h) plus our win32 jni_md.h, so no Windows JDK is needed to build.
    if(NOT DEFINED ENV{JAVA_HOME} AND NOT LB_JNI_INCLUDE)
        message(FATAL_ERROR "Set JAVA_HOME (or -DLB_JNI_INCLUDE=<dir with jni.h>)")
    endif()
    if(NOT LB_JNI_INCLUDE)
        set(LB_JNI_INCLUDE "$ENV{JAVA_HOME}/include")
    endif()

    add_library(lanbridge SHARED ${LB_CORE_SOURCES} wintun_win.cpp wintun_jni.cpp)
    target_include_directories(lanbridge PRIVATE ${LB_JNI_INCLUDE} ${CMAKE_CURRENT_SOURCE_DIR}/third_party/jni_win32)
    target_compile_definitions(lanbridge PRIVATE _WIN32_WINNT=0x0A00 WINVER=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
    target_compile_options(lanbridge PRIVATE -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden -ffunction-sections -fdata-sections)
    target_link_options(lanbridge PRIVATE -static -Wl,--gc-sections)
    target_link_libraries(lanbridge ws2_32 iphlpapi bcrypt shell32 ole32)
    set_target_properties(lanbridge PROPERTIES PREFIX "" OUTPUT_NAME "lanbridge")
else()
    add_library(lanbridge SHARED ${LB_CORE_SOURCES})

    target_compile_options(lanbridge PRIVATE
        -Wall -Wextra -Wno-unused-parameter
        -fvisibility=hidden -ffunction-sections -fdata-sections)

    # 16 KB page alignment (required on Android 15+ devices with 16 KB pages, harmless elsewhere)
    target_link_options(lanbridge PRIVATE -Wl,--gc-sections -Wl,-z,max-page-size=16384)

    find_library(log-lib log)
    target_link_libraries(lanbridge ${log-lib})
endif()

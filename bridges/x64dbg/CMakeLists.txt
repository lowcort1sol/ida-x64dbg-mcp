cmake_minimum_required(VERSION 3.24)
project(ix64mcp_x64dbg LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "x64dbg plugins are Windows-only")
endif()

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This target builds the x64 plugin. Use an x64 generator/toolchain.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(ix64mcp_x64dbg SHARED ix64mcp_x64dbg.cpp)

target_include_directories(ix64mcp_x64dbg PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../pluginsdk"
)

target_link_libraries(ix64mcp_x64dbg PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/../../pluginsdk/x64dbg.lib"
    "${CMAKE_CURRENT_LIST_DIR}/../../pluginsdk/x64bridge.lib"
    winhttp
)

target_compile_definitions(ix64mcp_x64dbg PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
)

set_target_properties(ix64mcp_x64dbg PROPERTIES
    OUTPUT_NAME "ix64mcp"
    SUFFIX ".dp64"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../../dist/x64dbg"
)

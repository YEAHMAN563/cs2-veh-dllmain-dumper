cmake_minimum_required(VERSION 3.16)
project(cs2_veh_dumper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Host EXE
add_executable(dumper
    src/dumper/main.cpp
    src/dumper/manual_map.cpp
)
target_include_directories(dumper PRIVATE src/dumper)
if(MSVC)
    target_compile_options(dumper PRIVATE /W3 /EHsc /MT)
    target_link_options(dumper PRIVATE "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
endif()

# Payload DLL
add_library(veh_dumper SHARED
    src/dll/dllmain.cpp
)
target_include_directories(veh_dumper PRIVATE src/dll)
if(MSVC)
    target_compile_options(veh_dumper PRIVATE /W3 /EHsc /MT)
    target_link_libraries(veh_dumper PRIVATE Psapi)
endif()

# Copy DLL next to EXE
add_custom_command(TARGET veh_dumper POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:veh_dumper>
        $<TARGET_FILE_DIR:dumper>
)

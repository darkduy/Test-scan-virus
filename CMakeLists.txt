cmake_minimum_required(VERSION 3.20)
project(BanVirusPro VERSION 2.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimization flags
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -flto")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-flto -Wl,--gc-sections")
endif()

# Version definitions
add_definitions(
    -DBANVIRUS_VERSION_STRING="${PROJECT_VERSION}"
    -DBANVIRUS_COMMIT_HASH="${GIT_COMMIT_HASH}"
)

add_executable(BanVirusPro BanVirusPro.cpp)

# Link libraries
target_link_libraries(BanVirusPro PRIVATE
    ws2_32 wininet psapi crypt32 shlwapi
    advapi32 shell32 ole32 user32
)

# Windows subsystem
set_target_properties(BanVirusPro PROPERTIES
    WIN32_EXECUTABLE TRUE
    LINK_FLAGS "/SUBSYSTEM:CONSOLE"
)

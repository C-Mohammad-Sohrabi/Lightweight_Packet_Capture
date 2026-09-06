cmake_minimum_required(VERSION 3.13)
project(snifer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ----------------------------------------------------------------------
# Find libpcap (POSIX and Npcap on Windows both expose this).
# On Windows with Npcap installed system-wide, find_package(PkgConfig)
# may find it. If not, users typically need to point CMake at the
# Npcap SDK or install a libpcap dev package.
# ----------------------------------------------------------------------
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PCAP libpcap)
endif()

find_path(PCAP_INCLUDE_DIR
  NAMES pcap/pcap.h pcap.h
  PATHS ${PCAP_INCLUDE_DIRS} /usr/include /usr/local/include
        ${CMAKE_SOURCE_DIR}/include
)

find_library(PCAP_LIBRARY
  NAMES pcap wpcap Packet
  PATHS ${PCAP_LIBRARY_DIRS}
        /usr/lib /usr/local/lib
        ${CMAKE_SOURCE_DIR}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
  REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR
)

add_executable(snifer main.c snifer.c)

target_include_directories(snifer PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(snifer PRIVATE ${PCAP_LIBRARY})

# Helpful warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(snifer PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Windows-specific notes:
# - On Windows, you usually need Npcap installed with the "WinPcap API-compatible
#   mode" enabled so the libpcap API is available.
# - If find_package(Pcap) fails, pass -DPCAP_INCLUDE_DIR and -DPCAP_LIBRARY
#   explicitly to CMake.
#
# Example Windows build using a typical Npcap layout:
#   cmake -B build -G "NMake Makefiles" ^
#     -DPCAP_INCLUDE_DIR="C:/Program Files/Npcap/sdk/include" ^
#     -DPCAP_LIBRARY="C:/Program Files/Npcap/sdk/lib/wpcap.lib"
#   cmake --build build
#
# Linux/macOS example:
#   cmake -B build
#   cmake --build build
#   ./build/snifer --list

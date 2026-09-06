cmake_minimum_required(VERSION 3.13)
project(snifer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ----------------------------------------------------------------------
# Find libpcap (POSIX and Npcap on Windows both expose this).
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

# ----------------------------------------------------------------------
# Find ncurses (for the menuconfig TUI)
# ----------------------------------------------------------------------
# Prefer ncurses6-config (Homebrew) for correct ABI-versioned libs.
# Only fall back to find_path/find_library if ncurses6-config is missing.
set(NCURSES_CFLAGS "")
set(NCURSES_LIBS "")

execute_process(COMMAND /opt/homebrew/opt/ncurses/bin/ncurses6-config --cflags
                OUTPUT_VARIABLE NCURSES_CFLAGS_RAW OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)
execute_process(COMMAND /opt/homebrew/opt/ncurses/bin/ncurses6-config --libs
                OUTPUT_VARIABLE NCURSES_LIBS_RAW OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)

if(NCURSES_CFLAGS_RAW AND NCURSES_LIBS_RAW)
  separate_arguments(NCURSES_CFLAGS_RAW UNIX_COMMAND "${NCURSES_CFLAGS_RAW}")
  separate_arguments(NCURSES_LIBS_RAW UNIX_COMMAND "${NCURSES_LIBS_RAW}")
  set(NCURSES_CFLAGS ${NCURSES_CFLAGS_RAW})
  set(NCURSES_LIBS ${NCURSES_LIBS_RAW})
else()
  # Fallback: try find_path / find_library
  find_path(NCURSES_CFLAGS
    NAMES ncurses.h
    PATHS /usr/include /usr/local/include
  )
  if(NCURSES_CFLAGS)
    set(NCURSES_CFLAGS "-I${NCURSES_CFLAGS}")
  endif()
  find_library(NCURSES_LIBS
    NAMES ncursesw ncurses
    PATHS /usr/lib /usr/local/lib
  )
endif()

add_executable(snifer src/main.c src/snifer.c src/menu.c)

target_include_directories(snifer PRIVATE
  ${PCAP_INCLUDE_DIR}
  include
)

if(NCURSES_CFLAGS)
  target_compile_options(snifer PRIVATE ${NCURSES_CFLAGS})
endif()

target_link_libraries(snifer PRIVATE
  ${PCAP_LIBRARY}
  ${NCURSES_LIBS}
)

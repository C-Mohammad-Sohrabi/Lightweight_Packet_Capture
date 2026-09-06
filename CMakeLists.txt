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
# Find ncurses (for the menuconfig TUI) — portable across macOS, Linux, and
# Windows (MSYS2 / Cygwin).  Falls back to CMake's built-in Curses module.
# ----------------------------------------------------------------------
find_package(Curses QUIET)
if(NOT CURSES_FOUND)
  # Homebrew on macOS installs ncurses in a non-standard path; try
  # ncurses6-config as a fallback before giving up.
  execute_process(COMMAND /opt/homebrew/opt/ncurses/bin/ncurses6-config --cflags
                  OUTPUT_VARIABLE NCURSES_CFLAGS_RAW OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
  execute_process(COMMAND /opt/homebrew/opt/ncurses/bin/ncurses6-config --libs
                  OUTPUT_VARIABLE NCURSES_LIBS_RAW OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
  if(NCURSES_CFLAGS_RAW AND NCURSES_LIBS_RAW)
    separate_arguments(NCURSES_CFLAGS_RAW UNIX_COMMAND "${NCURSES_CFLAGS_RAW}")
    separate_arguments(NCURSES_LIBS_RAW UNIX_COMMAND "${NCURSES_LIBS_RAW}")
    set(CURSES_INCLUDE_DIRS ${NCURSES_CFLAGS_RAW})
    set(CURSES_LIBRARIES ${NCURSES_LIBS_RAW})
    set(CURSES_FOUND TRUE)
  endif()
endif()

add_executable(snifer src/main.c src/snifer.c src/menu.c)

# Output binary to build/ (same as the Makefile convention)
set_target_properties(snifer PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

target_include_directories(snifer PRIVATE
  ${PCAP_INCLUDE_DIR}
  include
)

if(CURSES_FOUND)
  target_include_directories(snifer PRIVATE ${CURSES_INCLUDE_DIRS})
  target_link_libraries(snifer PRIVATE ${CURSES_LIBRARIES})
else()
  message(WARNING "ncurses not found — menuconfig TUI will not link. "
                  "Install ncurses (e.g. 'apt install libncurses-dev' on "
                  "Debian, 'brew install ncurses' on macOS, or 'pacman -S "
                  "ncurses' on MSYS2).")
endif()

target_link_libraries(snifer PRIVATE
  ${PCAP_LIBRARY}
)

# Custom target so `cmake --build build --target menuconfig` works
add_custom_target(menuconfig
  COMMAND snifer --menuconfig
  DEPENDS snifer
  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  COMMENT "Launching TUI capture setup..."
)

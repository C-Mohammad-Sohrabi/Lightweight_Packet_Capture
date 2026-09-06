# Makefile for snifer
#
# Platforms:
#   Linux, macOS (POSIX) with libpcap and ncurses installed.  Windows via
#   WSL, Cygwin, or MSYS2 (MinGW) with the same dependencies.
#
# Build:
#   make              Build the snifer binary (into build/)
#   make menuconfig   Launch the interactive TUI capture setup
#   make clean        Remove the entire build/ directory
#
# Run:
#   ./build/snifer                 Interactive mode
#   ./build/snifer --menuconfig    TUI setup mode
#   ./build/snifer --help          CLI flags

CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -std=c11

# --- ncurses detection ---
# Prefer ncurses6-config when available (Homebrew, etc.),
# fall back to pkg-config, then try -lncurses directly.
NCURSES_CFLAGS  := $(shell /opt/homebrew/opt/ncurses/bin/ncurses6-config --cflags 2>/dev/null || ncursesw6-config --cflags 2>/dev/null || echo "")
NCURSES_LIBS    := $(shell /opt/homebrew/opt/ncurses/bin/ncurses6-config --libs 2>/dev/null || ncursesw6-config --libs 2>/dev/null || echo "-lncursesw")

ifeq ($(NCURSES_CFLAGS),)
  NCURSES_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags ncursesw 2>/dev/null || pkg-config --cflags ncurses 2>/dev/null || echo "")
endif
ifeq ($(NCURSES_LIBS),-lncursesw)
  NCURSES_LIBS   := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs ncursesw 2>/dev/null || pkg-config --libs ncurses 2>/dev/null || echo "-lncursesw")
endif

LDFLAGS ?= -lpcap $(NCURSES_LIBS)

BUILD_DIR = build
OBJ_DIR   = $(BUILD_DIR)/obj_file
TARGET    = $(BUILD_DIR)/snifer

SRCS = src/main.c src/snifer.c src/menu.c
HDRS = include/snifer.h include/tui_menu.h
OBJS = $(SRCS:src/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean menuconfig

all: $(TARGET)

menuconfig: $(TARGET)
	@$(TARGET) --menuconfig

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: src/%.c $(HDRS) | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(NCURSES_CFLAGS) -I include -c -o $@ $<

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

src/%.o: src/%.c $(HDRS)
	$(CC) $(CFLAGS) $(NCURSES_CFLAGS) -I include -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR)

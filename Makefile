# Makefile for snifer
#
# Platforms:
#   Linux, macOS (POSIX) with libpcap installed.
#
# Windows note:
#   On Windows, build with CMake + Npcap instead; see CMakeLists.txt.
#   If you still want a Makefile-style build on Windows, use MinGW and
#   install Npcap + the associated libpcap dev files, then set:
#
#     make CC=x86_64-w64-mingw32-gcc LDFLAGS="-lwpcap -lucrtd"
#
# Build:
#   make
#   make clean
#
# Run:
#   ./snifer --list
#   sudo ./snifer --type tcp --port 80

CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -std=c11
LDFLAGS ?= -lpcap

SRCS = main.c snifer.c
OBJS = $(SRCS:.c=.o)
TARGET = snifer

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c snifer.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

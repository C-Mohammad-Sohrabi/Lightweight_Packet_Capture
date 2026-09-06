# Lightweight Packet Capture

A lightweight cross-platform packet sniffer written in C.

It uses the portable `libpcap` API:
* Linux / macOS / *BSD → `libpcap`
* Windows → `Npcap` (libpcap-compatible mode)

## What it does

* List available capture interfaces and pick one interactively
* Capture live packets and print:
  * timestamp
  * captured/original length
  * Ethernet type
  * IPv4/IPv6 source and destination
  * TCP/UDP ports and flags
  * hex dump of payloads when present
* Filter by:
  * packet type (`all`, `tcp`, `udp`, `icmp`, `arp`, `ipv4`, `ipv6`)
  * IPv4 address (source or destination)
  * TCP/UDP port

## Interactive mode

By default, the CLI opens a terminal menu:

1. Choose a capture interface from the listed devices.
2. Choose packet type(s) from the menu, including combinations like
   `tcp or udp`.
3. Optionally filter by an IPv4 address.
4. Optionally filter by a TCP/UDP port.
5. Start capturing and print matching packets until interrupted.

## Building

### POSIX (Linux, macOS)

Make sure `libpcap` development files are installed.

```bash
make
```

### Cross-platform (CMake)

```bash
cmake -B build
cmake --build build
```

On Windows with Npcap, you may need to point CMake at the Npcap SDK:

```bash
cmake -B build ^
  -DPCAP_INCLUDE_DIR="C:/Program Files/Npcap/sdk/include" ^
  -DPCAP_LIBRARY="C:/Program Files/Npcap/sdk/lib/wpcap.lib"
cmake --build build
```

## Usage

Interactive menu:

```bash
./snifer
```

One-shot mode:

```bash
./snifer --list
sudo ./snifer --type tcp --port 80
./snifer --type udp --ip 192.168.1.1
./snifer --type tcp --ip 10.0.0.5 --port 443
```

## Files

* `snifer.h` — public API
* `snifer.c` — capture and packet decoding
* `main.c` — CLI and interactive menu
* `Makefile` — macOS/Linux build
* `CMakeLists.txt` — cross-platform build

## Notes

* You usually need elevated privileges or a packet capture group to open
  interfaces.
* On macOS, WiFi capture may require explicit permissions.
* On Windows, install Npcap with WinPcap API-compatible mode enabled.
* This project is intentionally lightweight and focused on clarity,
  not on printing every detail under the sun.

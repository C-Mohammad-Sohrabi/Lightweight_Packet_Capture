/*
 * main.c - interactive menu + CLI for snifer
 *
 * Flow:
 *   1) Enumerate interfaces and let the user pick one (or auto-select).
 *   2) Choose packet type(s) from a text menu.
 *   3) Optionally filter by IPv4 address and/or port.
 *   4) Start the capture and print packets.
 */

#include "snifer.h"
#include "tui_menu.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

/* ---------------------------------------------------------------------------
 * Helpers
 * --------------------------------------------------------------------------- */

/* Read a line from stdin. Returns length, or -1 on EOF/error. */
static int read_line(char *buf, size_t size)
{
    if (size == 0) return -1;
    if (fgets(buf, (int)size, stdin) == NULL) {
        buf[0] = '\0';
        return -1;
    }
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return (int)len;
}

/* Trim leading/trailing whitespace in-place. */
static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* ---------------------------------------------------------------------------
 * Interface selection
 * --------------------------------------------------------------------------- */

/* Pick an interface from the device list. Stores the device pointer in
 * *dev_out and returns 0 on success, -1 on error, 1 if cancelled. */
static int pick_interface(pcap_if_t *alldevs, pcap_if_t **dev_out)
{
    /* Count devices */
    int count = 0;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next)
        count++;

    if (count == 0) {
        fprintf(stderr, "snifer: no capture interfaces found.\n");
        return -1;
    }

    if (count == 1) {
        *dev_out = alldevs;
        return 0;
    }

    printf("\nAvailable interfaces:\n");
    int i = 1;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next, i++) {
        printf("  %d) %s", i, d->name);
        if (d->description)
            printf("  -- %s", d->description);
        printf("\n");
        if (d->addresses) {
            for (pcap_addr_t *a = d->addresses; a; a = a->next) {
                if (!a->addr) continue;
                if (a->addr->sa_family == AF_INET) {
                    char buf[INET_ADDRSTRLEN];
                    struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                    if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)))
                        printf("        IPv4: %s\n", buf);
                } else if (a->addr->sa_family == AF_INET6) {
                    char buf[INET6_ADDRSTRLEN];
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)a->addr;
                    if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)))
                        printf("        IPv6: %s\n", buf);
                }
            }
        }
    }

    for (;;) {
        printf("\nChoose an interface number [1-%d, or 0 to cancel]: ", count);
        fflush(stdout);
        char line[64];
        if (read_line(line, sizeof(line)) < 0) {
            printf("\n");
            return 1;
        }
        char *t = trim(line);
        if (*t == '\0') continue;
        char *end = NULL;
        unsigned long v = strtoul(t, &end, 10);
        if (*end != '\0') {
            printf("Enter a number, please.\n");
            continue;
        }
        if (v == 0) return 1; /* cancelled */
        if (v > (unsigned long)count) {
            printf("Number out of range. Enter 1-%d.\n", count);
            continue;
        }
        pcap_if_t *d = alldevs;
        for (unsigned long j = 1; j < v; j++) d = d->next;
        *dev_out = d;
        return 0;
    }
}

/* ---------------------------------------------------------------------------
 * Packet type selection
 * --------------------------------------------------------------------------- */

/* Protocol names recognised by snifer.c's filter builder. */
static const char *protocol_names[] = {
    "tcp", "udp", "icmp", "arp", "ipv4", "ipv6", NULL
};
static const char *protocol_labels[] = {
    "TCP", "UDP", "ICMP / ICMPv6", "ARP", "IPv4", "IPv6", NULL
};

/* Build an "or"-expression from selected protocols. Caller must free. */
static char *build_type_expr(const int *selected, int n_protos)
{
    /* Compute max length: sum of names + " or " separators + parens */
    size_t len = 2; /* parens */
    int count = 0;
    for (int i = 0; i < n_protos; i++) {
        if (selected[i]) {
            if (count > 0) len += 4; /* " or " */
            len += strlen(protocol_names[i]);
            count++;
        }
    }
    if (count == 0) return strdup("all");
    if (count == 1) {
        for (int i = 0; i < n_protos; i++)
            if (selected[i]) return strdup(protocol_names[i]);
    }

    char *expr = malloc(len + 1);
    if (!expr) return NULL;
    size_t pos = 0;
    pos += snprintf(expr + pos, len + 1 - pos, "(");
    int first = 1;
    for (int i = 0; i < n_protos; i++) {
        if (selected[i]) {
            if (!first) pos += snprintf(expr + pos, len + 1 - pos, " or ");
            pos += snprintf(expr + pos, len + 1 - pos, "%s", protocol_names[i]);
            first = 0;
        }
    }
    pos += snprintf(expr + pos, len + 1 - pos, ")");
    return expr;
}

static int run_packet_type_menu(char **type_out)
{
    int n = 0;
    while (protocol_names[n]) n++;

    printf("\nSelect packet types (space to toggle, enter when done):\n");
    int *selected = calloc((size_t)n, sizeof(int));
    if (!selected) return -1;

    /* Default: select "all" (none selected → "all" is the output) */
    int cursor = 0;
    int done = 0;

    while (!done) {
        printf("\n");
        for (int i = 0; i < n; i++) {
            printf("  %s %s %s\n",
                   i == cursor ? ">" : " ",
                   selected[i] ? "[*]" : "[ ]",
                   protocol_labels[i]);
        }
        printf("\n  Navigate with up/down (or j/k), space to toggle, enter to confirm, q to cancel.\n");
        printf("  > ");

        char line[16];
        if (read_line(line, sizeof(line)) < 0) {
            free(selected);
            return -1;
        }

        if (strcmp(line, "q") == 0 || strcmp(line, "Q") == 0) {
            free(selected);
            return -1;
        }

        if (strcmp(line, "") == 0 || strcmp(line, "\n") == 0) {
            done = 1;
        } else if (strcmp(line, "j") == 0) {
            cursor = (cursor + 1) % n;
        } else if (strcmp(line, "k") == 0) {
            cursor = (cursor + n - 1) % n;
        } else if (strcmp(line, "up") == 0 || strcmp(line, "\033[A") == 0) {
            cursor = (cursor + n - 1) % n;
        } else if (strcmp(line, "down") == 0 || strcmp(line, "\033[B") == 0) {
            cursor = (cursor + 1) % n;
        } else if (line[0] == ' ') {
            selected[cursor] = !selected[cursor];
        }
    }

    *type_out = build_type_expr(selected, n);
    free(selected);
    return *type_out ? 0 : -1;
}

/* ---------------------------------------------------------------------------
 * IP address input
 * --------------------------------------------------------------------------- */

static int read_ip_address(char *out, size_t out_size)
{
    printf("\nFilter by IPv4 address? (leave empty for none): ");
    fflush(stdout);

    for (;;) {
        char line[128];
        if (read_line(line, sizeof(line)) < 0) {
            out[0] = '\0';
            return -1;
        }
        char *t = trim(line);
        if (*t == '\0') {
            out[0] = '\0';
            return 0;
        }
        struct in_addr addr;
        if (inet_pton(AF_INET, t, &addr) != 1) {
            printf("Not a valid IPv4 address. Try again or leave empty: ");
            fflush(stdout);
            continue;
        }
        snprintf(out, out_size, "%s", t);
        return 0;
    }
}

/* ---------------------------------------------------------------------------
 * Port input
 * --------------------------------------------------------------------------- */

static int read_port(unsigned short *out)
{
    printf("\nFilter by TCP/UDP port? (leave empty for none): ");
    fflush(stdout);

    for (;;) {
        char line[64];
        if (read_line(line, sizeof(line)) < 0) {
            *out = 0;
            return -1;
        }
        char *t = trim(line);
        if (*t == '\0') {
            *out = 0;
            return 0;
        }
        char *end = NULL;
        unsigned long v = strtoul(t, &end, 10);
        if (*end != '\0' || v == 0 || v > 65535) {
            printf("Invalid port (1-65535). Try again or leave empty: ");
            fflush(stdout);
            continue;
        }
        *out = (unsigned short)v;
        return 0;
    }
}

/* ---------------------------------------------------------------------------
 * CLI parsing
 * --------------------------------------------------------------------------- */

static void print_usage(const char *prog)
{
    printf("Lightweight Packet Capture (snifer)\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  --help              Show this help message\n");
    printf("  --list              List available interfaces\n");
    printf("  --interface IFACE   Use specific interface\n");
    printf("  --type TYPE         Packet type: all, tcp, udp, icmp, arp, ipv4, ipv6\n");
    printf("  --ip ADDR           Filter by IPv4 address\n");
    printf("  --port PORT         Filter by TCP/UDP port\n");
    printf("  --menuconfig        Launch the TUI setup menu\n");
    printf("\n");
    printf("With no arguments, launches the interactive setup.\n");
}

/* ---------------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    /* Parse CLI flags */
    struct sniffer_options opts;
    memset(&opts, 0, sizeof(opts));
    const char *cli_interface = NULL;
    int use_interactive = 1;
    int want_help = 0;
    int want_list = 0;
    int want_menuconfig = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            want_help = 1;
        } else if (strcmp(argv[i], "--list") == 0) {
            want_list = 1;
        } else if (strcmp(argv[i], "--menuconfig") == 0 ||
                   strcmp(argv[i], "--menu") == 0) {
            want_menuconfig = 1;
            use_interactive = 0;
            if (!isatty(STDIN_FILENO) && !isatty(STDOUT_FILENO)) {
                fprintf(stderr, "snifer: --menuconfig requires a terminal.\n");
                free((void *)opts.packet_type);
                free((void *)opts.ip_addr);
                return 1;
            }
        } else if (strcmp(argv[i], "--interface") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "snifer: --interface requires an argument.\n");
                return 1;
            }
            cli_interface = argv[++i];
            use_interactive = 0;
        } else if (strcmp(argv[i], "--type") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "snifer: --type requires an argument.\n");
                return 1;
            }
            opts.packet_type = strdup(argv[++i]);
            if (!opts.packet_type) { fprintf(stderr, "snifer: out of memory.\n"); return 1; }
            use_interactive = 0;
        } else if (strcmp(argv[i], "--ip") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "snifer: --ip requires an argument.\n");
                free((void *)opts.packet_type);
                return 1;
            }
            opts.ip_addr = strdup(argv[++i]);
            if (!opts.ip_addr) { free((void *)opts.packet_type); fprintf(stderr, "snifer: out of memory.\n"); return 1; }
            use_interactive = 0;
        } else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "snifer: --port requires an argument.\n");
                free((void *)opts.packet_type);
                free((void *)opts.ip_addr);
                return 1;
            }
            char *end = NULL;
            unsigned long port = strtoul(argv[++i], &end, 10);
            if (*end != '\0' || port == 0 || port > 65535) {
                fprintf(stderr, "snifer: invalid port: %s\n", argv[i]);
                free((void *)opts.packet_type);
                free((void *)opts.ip_addr);
                return 1;
            }
            opts.port = (unsigned short)port;
            use_interactive = 0;
        } else {
            fprintf(stderr, "snifer: unknown option: %s\n", argv[i]);
            fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);
            free((void *)opts.packet_type);
            free((void *)opts.ip_addr);
            return 1;
        }
    }

    if (want_help) {
        print_usage(argv[0]);
        free((void *)opts.packet_type);
        free((void *)opts.ip_addr);
        return 0;
    }

    if (want_list) {
        char errbuf[PCAP_ERRBUF_SIZE];
        int n = sniffer_list_devices(errbuf, sizeof(errbuf));
        free((void *)opts.packet_type);
        free((void *)opts.ip_addr);
        return n >= 0 ? 0 : 1;
    }

    /* Enumerate interfaces */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "snifer: failed to enumerate interfaces: %s\n", errbuf);
        free((void *)opts.packet_type);
        free((void *)opts.ip_addr);
        return 1;
    }
    if (alldevs == NULL) {
        fprintf(stderr, "snifer: no capture interfaces found.\n");
        free((void *)opts.packet_type);
        free((void *)opts.ip_addr);
        return 1;
    }

    if (want_menuconfig) {
        /* TUI menuconfig mode */
        const char *selected_dev_name = NULL;
        struct sniffer_options menu_opts;
        memset(&menu_opts, 0, sizeof(menu_opts));

        enum menu_result mr = menu_capture_setup(alldevs, &selected_dev_name,
                                                  &menu_opts, errbuf, sizeof(errbuf));
        if (mr == MENU_RESULT_CANCEL) {
            pcap_freealldevs(alldevs);
            free((void *)opts.packet_type);
            free((void *)opts.ip_addr);
            printf("Cancelled.\n");
            return 0;
        }
        if (mr == MENU_RESULT_ERROR) {
            pcap_freealldevs(alldevs);
            free((void *)opts.packet_type);
            free((void *)opts.ip_addr);
            fprintf(stderr, "snifer: menuconfig error.\n");
            return 1;
        }

        if (!selected_dev_name) {
            pcap_freealldevs(alldevs);
            free((void *)opts.packet_type);
            free((void *)opts.ip_addr);
            free((void *)menu_opts.packet_type);
            free((void *)menu_opts.ip_addr);
            fprintf(stderr, "snifer: no interface selected.\n");
            return 1;
        }

        /* Open the selected interface */
        pcap_t *handle = sniffer_open_interface(selected_dev_name, errbuf, sizeof(errbuf));
        if (handle == NULL) {
            fprintf(stderr, "snifer: cannot open %s: %s\n", selected_dev_name, errbuf);
            pcap_freealldevs(alldevs);
            free((void *)opts.packet_type);
            free((void *)opts.ip_addr);
            free((void *)menu_opts.packet_type);
            free((void *)menu_opts.ip_addr);
            return 1;
        }

        /* Copy device name before freeing the list (selected_dev_name points into alldevs) */
        char dev_name_buf[256];
        snprintf(dev_name_buf, sizeof(dev_name_buf), "%s", selected_dev_name);

        pcap_freealldevs(alldevs);

        /* Print settings summary */
        printf("\nInterface: %s\n", dev_name_buf);
        printf("Packet type: %s\n", menu_opts.packet_type ? menu_opts.packet_type : "(all)");
        printf("IPv4 filter: %s\n", menu_opts.ip_addr ? menu_opts.ip_addr : "(none)");
        printf("Port filter: %u\n", menu_opts.port);
        printf("\n");

        printf("Starting capture... (Ctrl+C to stop)\n\n");
        int rc = sniffer_run_capture(handle, &menu_opts);
        sniffer_close(handle);

        free((void *)menu_opts.packet_type);
        free((void *)menu_opts.ip_addr);
        free((void *)opts.packet_type);
        free((void *)opts.ip_addr);
        return rc == 0 ? 0 : 1;
    }

    pcap_if_t *selected_dev = NULL;
    char *type_expr = NULL; /* track if we allocated type_expr ourselves */

    if (use_interactive) {
        /* Interactive menu mode */
        printf("=== Lightweight Packet Capture (snifer) ===\n");

        if (pick_interface(alldevs, &selected_dev) != 0) {
            pcap_freealldevs(alldevs);
            free((void *)opts.packet_type);
            free((void *)opts.ip_addr);
            printf("Cancelled.\n");
            return 0;
        }

        if (run_packet_type_menu(&type_expr) != 0) {
            pcap_freealldevs(alldevs);
            free((void *)opts.packet_type);
            free((void *)opts.ip_addr);
            free(type_expr);
            printf("Cancelled.\n");
            return 0;
        }

        opts.packet_type = type_expr; /* type_expr is strdup'd */

        char ip[INET_ADDRSTRLEN + 1] = {0};
        if (read_ip_address(ip, sizeof(ip)) != 0) {
            pcap_freealldevs(alldevs);
            free((void *)opts.packet_type);
            free((void *)opts.ip_addr);
            return 1;
        }
        if (ip[0]) {
            opts.ip_addr = strdup(ip);
            if (!opts.ip_addr) {
                pcap_freealldevs(alldevs);
                free((void *)opts.packet_type);
                return 1;
            }
        }

        unsigned short port = 0;
        if (read_port(&port) != 0) {
            pcap_freealldevs(alldevs);
            free((void *)opts.packet_type);
            free((void *)opts.ip_addr);
            return 1;
        }
        opts.port = port;

        /* Print summary */
        printf("\n--- Capture Setup ---\n");
        printf("Interface: %s", selected_dev->name);
        if (selected_dev->description)
            printf("  (%s)", selected_dev->description);
        printf("\n");
        printf("Packet type: %s\n", opts.packet_type ? opts.packet_type : "(all)");
        printf("IPv4 filter: %s\n", opts.ip_addr ? opts.ip_addr : "(none)");
        printf("Port filter: %u\n", opts.port);
        printf("----------------------\n\n");
    } else {
        /* CLI one-shot mode */
        if (cli_interface) {
            /* Find the named interface in the list */
            for (pcap_if_t *d = alldevs; d; d = d->next) {
                if (strcmp(d->name, cli_interface) == 0) {
                    selected_dev = d;
                    break;
                }
            }
            if (!selected_dev) {
                fprintf(stderr, "snifer: interface '%s' not found.\n", cli_interface);
                pcap_freealldevs(alldevs);
                free((void *)opts.packet_type);
                free((void *)opts.ip_addr);
                return 1;
            }
        } else {
            selected_dev = alldevs; /* auto-select first */
        }
    }

    /* Open the interface */
    pcap_t *handle = sniffer_open_interface(selected_dev->name, errbuf, sizeof(errbuf));
    if (handle == NULL) {
        fprintf(stderr, "snifer: cannot open %s: %s\n", selected_dev->name, errbuf);
        pcap_freealldevs(alldevs);
        free((void *)opts.packet_type);
        free((void *)opts.ip_addr);
        return 1;
    }

    /* Copy device name before freeing the list (selected_dev->name points into alldevs) */
    char cli_dev_name[256];
    snprintf(cli_dev_name, sizeof(cli_dev_name), "%s", selected_dev->name);

    /* Free the device list now that we've opened the interface */
    pcap_freealldevs(alldevs);
    alldevs = NULL;

    /* Print summary for CLI mode */
    if (!use_interactive) {
        printf("Interface: %s\n", cli_dev_name);
        printf("Packet type: %s\n", opts.packet_type ? opts.packet_type : "(all)");
        printf("IPv4 filter: %s\n", opts.ip_addr ? opts.ip_addr : "(none)");
        printf("Port filter: %u\n", opts.port);
    }

    printf("Starting capture... (Ctrl+C to stop)\n\n");
    int rc = sniffer_run_capture(handle, &opts);
    sniffer_close(handle);

    /* Cleanup */
    free((void *)opts.packet_type);
    free((void *)opts.ip_addr);

    return rc == 0 ? 0 : 1;
}

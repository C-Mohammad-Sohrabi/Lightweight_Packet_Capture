/*
 * main.c - interactive menu CLI for snifer
 *
 * Flow:
 *   1) List interfaces and select one (or auto-select if only one exists).
 *   2) Choose packet type(s) from a terminal menu.
 *   3) Optionally filter by IPv4 address and/or port.
 *   4) Start the capture and print packets.
 *
 * The capture itself still uses the snifer API from snifer.c.
 */

#include "snifer.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Minimal terminal helpers
 * --------------------------------------------------------------------------- */

/* Read an entire line from stdin. Returns number of chars stored, or -1 on
 * EOF/error. The buffer is always NUL-terminated if buf_size > 0. */
static int read_line(char *buf, size_t buf_size)
{
    if (buf_size == 0) {
        return -1;
    }
    if (fgets(buf, (int)buf_size, stdin) == NULL) {
        buf[0] = '\0';
        return -1;
    }
    size_t len = strlen(buf);
    /* drop trailing newline */
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
        len--;
    }
    /* also drop carriage return for copy/paste safety */
    if (len > 0 && buf[len - 1] == '\r') {
        buf[len - 1] = '\0';
        len--;
    }
    return (int)len;
}

/* Trim leading/trailing whitespace in-place. */
static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

/* ---------------------------------------------------------------------------
 * Device list display + selection
 * --------------------------------------------------------------------------- */

static void show_interfaces(const pcap_if_t *alldevs)
{
    const pcap_if_t *d = NULL;
    int i = 1;
    for (d = alldevs; d != NULL; d = d->next) {
        printf("  %d) %s", i, d->name);
        if (d->description) {
            printf("  -- %s", d->description);
        }
        fputc('\n', stdout);

        if (d->addresses != NULL) {
            const pcap_addr_t *a = NULL;
            for (a = d->addresses; a != NULL; a = a->next) {
                if (a->addr == NULL) continue;
                if (a->addr->sa_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                    char buf[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, &sin->sin_addr, buf,
                                  sizeof(buf))) {
                        printf("        IPv4: %s\n", buf);
                    }
                } else if (a->addr->sa_family == AF_INET6) {
                    struct sockaddr_in6 *sin6 =
                        (struct sockaddr_in6 *)a->addr;
                    char buf[INET6_ADDRSTRLEN];
                    if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf,
                                  sizeof(buf))) {
                        printf("        IPv6: %s\n", buf);
                    }
                }
            }
        }
        i++;
    }
}

typedef struct {
    pcap_if_t *selected;
    int index;
} device_choice_t;

static int pick_interface(device_choice_t *out, char *errbuf,
                          size_t errbuf_size)
{
    pcap_if_t *alldevs = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "snifer: failed to enumerate interfaces: %s\n",
                errbuf);
        return -1;
    }
    if (alldevs == NULL) {
        fprintf(stderr,
                "snifer: no capture interfaces found.\n"
                "        You may need elevated privileges or packet capture\n"
                "        permissions.\n");
        return -1;
    }

    int count = 0;
    for (const pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        count++;
    }

    if (count == 0) {
        fprintf(stderr,
                "snifer: no usable interfaces found.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (count == 1) {
        out->selected = alldevs;
        out->index = 1;
        return 0;
    }

    printf("\nAvailable interfaces:\n");
    show_interfaces(alldevs);
    printf("\nChoose an interface number [1-%d]: ", count);
    fflush(stdout);

    char line[64];
    int choice = 0;
    int ok = 0;
    while (!ok) {
        int n = read_line(line, sizeof(line));
        if (n < 0) {
            fprintf(stderr, "\nInput cancelled.\n");
            pcap_freealldevs(alldevs);
            return -1;
        }
        char *t = trim(line);
        if (*t == '\0') {
            printf("Enter a number [1-%d]: ", count);
            fflush(stdout);
            continue;
        }
        char *end = NULL;
        unsigned long v = strtoul(t, &end, 10);
        if (*end != '\0' || v == 0 || v > (unsigned long)count) {
            printf("Invalid number, enter [1-%d]: ", count);
            fflush(stdout);
            continue;
        }
        choice = (int)v;
        ok = 1;
    }

    pcap_if_t *d = alldevs;
    for (int i = 1; i < choice; i++) {
        if (d == NULL || d->next == NULL) {
            fprintf(stderr, "snifer: unexpected interface list.\n");
            pcap_freealldevs(alldevs);
            return -1;
        }
        d = d->next;
    }
    out->selected = d;
    out->index = choice;
    return 0;
}

/* ---------------------------------------------------------------------------
 * Packet type menu
 * --------------------------------------------------------------------------- */

typedef struct {
    char *type;
    const char *label;
    const char *hint;
} packet_type_option_t;

static const packet_type_option_t packet_type_options[] = {
    { "all",   "All packets",                 "any" },
    { "tcp",   "TCP",                         "tcp only" },
    { "udp",   "UDP",                         "udp only" },
    { "icmp",  "ICMP / ICMPv6",               "icmp/icmp6" },
    { "arp",   "ARP",                         "arp only" },
    { "ipv4",  "IPv4",                        "ip only" },
    { "ipv6",  "IPv6",                        "ip6 only" },
    { NULL,    NULL,                          NULL }
};

static void show_packet_type_menu(void)
{
    printf("\nSelect packet type(s) to capture:\n");
    int i = 1;
    for (int k = 0; packet_type_options[k].type != NULL; k++) {
        printf("  %d) %s", i, packet_type_options[k].label);
        if (packet_type_options[k].hint) {
            printf("  (%s)", packet_type_options[k].hint);
        }
        fputc('\n', stdout);
        i++;
    }
    printf("  0) Back\n");
}

/* Build a braced list of selected types for filter construction. */
typedef struct {
    char **items;
    int count;
    int cap;
} strlist_t;

static void strlist_init(strlist_t *list)
{
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static void strlist_add(strlist_t *list, const char *s)
{
    if (list->count >= list->cap) {
        int nc = list->cap == 0 ? 8 : list->cap * 2;
        char **p = realloc(list->items, (size_t)nc * sizeof(char *));
        if (p == NULL) {
            return;
        }
        list->items = p;
        list->cap = nc;
    }
    list->items[list->count] = strdup(s);
    if (list->items[list->count]) {
        list->count++;
    }
}

static void strlist_free(strlist_t *list)
{
    for (int i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

/* Persistent multi-select accumulator so the user can build a combination
 * like "tcp or udp", then optionally go back and change it. */
static strlist_t selected_types;

static int run_packet_type_menu(void)
{
    strlist_init(&selected_types);

    for (;;) {
        printf("\nCurrent selection: ");
        if (selected_types.count == 0) {
            printf("(none -- captures all packets)\n");
        } else {
            for (int i = 0; i < selected_types.count; i++) {
                if (i > 0) {
                    fputc(',', stdout);
                }
                printf(" %s", selected_types.items[i]);
            }
            fputc('\n', stdout);
        }

        show_packet_type_menu();
        printf("Choice [number, comma-separated]: ");

        char line[256];
        int n = read_line(line, sizeof(line));
        if (n < 0) {
            fprintf(stderr, "\nInput cancelled.\n");
            strlist_free(&selected_types);
            return -1;
        }
        char *t = trim(line);
        if (*t == '0' && t[1] == '\0') {
            /* Back: clear selection for this step but keep going */
            strlist_free(&selected_types);
            continue;
        }
        if (*t == '\0') {
            continue;
        }

        /* Parse comma-separated numbers. */
        int ok = 1;
        char *save = NULL;
        char *tok = strtok_r(t, ",", &save);
        while (tok) {
            tok = trim(tok);
            if (*tok == '\0') {
                tok = strtok_r(NULL, ",", &save);
                continue;
            }
            char *end = NULL;
            unsigned long v = strtoul(tok, &end, 10);
            if (*end != '\0' || v == 0 || v > (unsigned long)8) {
                ok = 0;
                break;
            }
            int idx = (int)v - 1;
            const packet_type_option_t *opt =
                &packet_type_options[idx];
            strlist_add(&selected_types, opt->type);
            tok = strtok_r(NULL, ",", &save);
        }

        if (!ok) {
            printf("Invalid selection. Try again.\n");
            strlist_free(&selected_types);
            continue;
        }

        printf("Added. Press Enter to continue or edit again.\n");
        printf("Enter empty line to finish selecting types.\n");
        char again[64];
        int rn = read_line(again, sizeof(again));
        if (rn >= 0 && trim(again)[0] != '\0') {
            /* User entered something non-empty: treat as retry of menu. */
            strlist_free(&selected_types);
            continue;
        }
        break;
    }

    if (selected_types.count == 0) {
        /* Default to all */
        strlist_add(&selected_types, "all");
    }

    return 0;
}

/* Translate the selected type list into the filter string expected by
 * snifer_options.packet_type. We join multiple types with " or " so the
 * resulting expression is "(tcp or udp)", etc. */
static int build_packet_type_filter(strlist_t *list, char *out,
                                    size_t out_size)
{
    if (list->count == 0) {
        snprintf(out, out_size, "all");
        return 0;
    }
    if (list->count == 1) {
        snprintf(out, out_size, "%s", list->items[0]);
        return 0;
    }
    out[0] = '\0';
    size_t pos = 0;
    for (int i = 0; i < list->count; i++) {
        if (i > 0) {
            if (pos < out_size - 1) out[pos++] = ' ';
            if (pos < out_size - 1) out[pos++] = 'o';
            if (pos < out_size - 1) out[pos++] = 'r';
            if (pos < out_size - 1) out[pos++] = ' ';
        }
        size_t len = strnlen(list->items[i], out_size);
        if (pos + len < out_size) {
            memcpy(out + pos, list->items[i], len);
            pos += len;
        }
    }
    out[pos] = '\0';
    return 0;
}

/* ---------------------------------------------------------------------------
 * IP input
 * --------------------------------------------------------------------------- */

static int read_ip_address(char *out, size_t out_size)
{
    printf("\nFilter by IPv4 address? (leave empty for none): ");
    fflush(stdout);

    char line[128];
    for (;;) {
        int n = read_line(line, sizeof(line));
        if (n < 0) {
            fprintf(stderr, "\nInput cancelled.\n");
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
        if (out_size > 0) {
            snprintf(out, out_size, "%s", t);
        }
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

    char line[64];
    for (;;) {
        int n = read_line(line, sizeof(line));
        if (n < 0) {
            fprintf(stderr, "\nInput cancelled.\n");
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
 * Review + start
 * --------------------------------------------------------------------------- */

static void print_summary(const struct sniffer_options *opts,
                          const pcap_if_t *device)
{
    printf("\n--- Capture Setup ---\n");
    if (device) {
        printf("Interface: %s", device->name);
        if (device->description) {
            printf("  (%s)", device->description);
        }
        fputc('\n', stdout);
    } else {
        printf("Interface: (auto)\n");
    }
    printf("Packet type: %s\n",
           opts->packet_type ? opts->packet_type : "(all)");
    printf("IPv4 filter: %s\n",
           opts->ip_addr ? opts->ip_addr : "(none)");
    printf("Port filter: %u\n", opts->port);
    printf("----------------------\n\n");
}

/* ---------------------------------------------------------------------------
 * Main interactive entry point
 * --------------------------------------------------------------------------- */

int main(void)
{
    /* Make sure output appears immediately; the menu and capture loop both
     * print frequently and should not get interleaved. */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    char errbuf[PCAP_ERRBUF_SIZE];

    printf("=== Lightweight Packet Capture (snifer) ===\n");

    device_choice_t devchoice = { NULL, 0 };
    if (pick_interface(&devchoice, errbuf, sizeof(errbuf)) != 0) {
        return 1;
    }

    if (run_packet_type_menu() != 0) {
        return 1;
    }

    char ip[INET_ADDRSTRLEN + 1] = {0};
    if (read_ip_address(ip, sizeof(ip)) != 0) {
        return 1;
    }

    unsigned short port = 0;
    if (read_port(&port) != 0) {
        return 1;
    }

    /* Build the final options. */
    struct sniffer_options opts;
    memset(&opts, 0, sizeof(opts));
    {
        char pt[256] = {0};
        if (build_packet_type_filter(&selected_types, pt,
                                     sizeof(pt)) != 0) {
            fprintf(stderr, "snifer: failed to build packet type filter.\n");
            strlist_free(&selected_types);
            return 1;
        }
        opts.packet_type = pt;
    }
    opts.ip_addr = ip[0] ? ip : NULL;
    opts.port = port;
    opts.snaplen = 65535;

    strlist_free(&selected_types);

    /* Open the exact interface the user chose, once, before capture. */
    pcap_t *handle = sniffer_open_interface(devchoice.selected->name,
                                            errbuf,
                                            sizeof(errbuf));
    if (handle == NULL) {
        fprintf(stderr, "snifer: cannot open %s: %s\n",
                devchoice.selected->name, errbuf);
        return 1;
    }

    print_summary(&opts, devchoice.selected);

    printf("Starting capture... (Ctrl+C to stop)\n\n");
    int rc = sniffer_run_capture(handle, &opts);
    /* sniffer_run_capture closes the handle on all paths. */
    return rc == 0 ? 0 : 1;
}

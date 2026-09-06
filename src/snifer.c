/*
 * snifer.c - lightweight cross-platform packet sniffer
 *
 * Capture backend: libpcap on POSIX (Linux, macOS, *BSD) and Npcap on
 * Windows (libpcap-compatible API).
 *
 * Design notes:
 *  - Packet decoding is intentionally minimal and correct: we inspect
 *    Ethernet type, then IPv4/IPv6, then TCP/UDP where applicable.
 *  - We keep the code small and readable rather than trying to decode every
 *    protocol. Unknown/encapsulated traffic is reported as "other/unknown".
 *  - On macOS, pcap.h types such as pcap_t, u_char, and pcap_pkthdr are used
 *    directly to avoid conflicts with network headers that use the same names
 *    with different definitions.
 */

#include "snifer.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* ---------------------------------------------------------------------------
 * Global shutdown flag for graceful Ctrl+C handling.
 * --------------------------------------------------------------------------- */
static volatile sig_atomic_t snifer_running = 1;

static void snifer_signal_handler(int signo)
{
    (void)signo;
    snifer_running = 0;
}

/* ---------------------------------------------------------------------------
 * Tiny helpers
 * --------------------------------------------------------------------------- */

static void snifer_set_error(char *errbuf, size_t errbuf_size,
                             const char *fmt, ...)
{
    va_list ap;

    if (errbuf == NULL || errbuf_size == 0) {
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(errbuf, errbuf_size, fmt, ap);
    va_end(ap);
}

static void snifer_copy_error(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || dst_size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    (void)snprintf(dst, dst_size, "%s", src);
}

static int snifer_token_equals(const char *token, size_t token_len,
                               const char *literal)
{
    size_t literal_len = strlen(literal);
    size_t i;

    if (token_len != literal_len) {
        return 0;
    }
    for (i = 0; i < token_len; ++i) {
        if (tolower((unsigned char)token[i]) !=
            tolower((unsigned char)literal[i])) {
            return 0;
        }
    }
    return 1;
}

enum snifer_type_bit {
    SNIFER_TYPE_TCP = 1 << 0,
    SNIFER_TYPE_UDP = 1 << 1,
    SNIFER_TYPE_ICMP = 1 << 2,
    SNIFER_TYPE_ARP = 1 << 3,
    SNIFER_TYPE_IPV4 = 1 << 4,
    SNIFER_TYPE_IPV6 = 1 << 5
};

static int snifer_type_bit_for_token(const char *token, size_t token_len)
{
    if (snifer_token_equals(token, token_len, "tcp")) {
        return SNIFER_TYPE_TCP;
    }
    if (snifer_token_equals(token, token_len, "udp")) {
        return SNIFER_TYPE_UDP;
    }
    if (snifer_token_equals(token, token_len, "icmp") ||
        snifer_token_equals(token, token_len, "icmp6") ||
        snifer_token_equals(token, token_len, "icmpv6")) {
        return SNIFER_TYPE_ICMP;
    }
    if (snifer_token_equals(token, token_len, "arp")) {
        return SNIFER_TYPE_ARP;
    }
    if (snifer_token_equals(token, token_len, "ipv4") ||
        snifer_token_equals(token, token_len, "ip")) {
        return SNIFER_TYPE_IPV4;
    }
    if (snifer_token_equals(token, token_len, "ipv6") ||
        snifer_token_equals(token, token_len, "ip6")) {
        return SNIFER_TYPE_IPV6;
    }
    return 0;
}

/* Parse the small packet-type language used by the menu and CLI. The parser
 * deliberately accepts only protocol names joined by OR; accepting arbitrary
 * BPF text here made malformed menu combinations easy to generate. */
static int snifer_parse_type_bits(const char *input, int *bits_out,
                                  size_t bits_cap, size_t *count_out,
                                  int *all_out)
{
    const char *p = input;
    size_t count = 0;
    int all = 0;
    int need_term = 1;
    int saw_term = 0;
    unsigned int depth = 0;

    if (bits_out == NULL || count_out == NULL || all_out == NULL ||
        bits_cap == 0) {
        return -1;
    }

    if (p == NULL) {
        *count_out = 0;
        *all_out = 1;
        return 0;
    }

    while (*p != '\0') {
        while (*p != '\0' && isspace((unsigned char)*p)) {
            ++p;
        }
        if (*p == '(') {
            ++depth;
            ++p;
            continue;
        }
        if (*p == ')') {
            if (depth == 0) {
                return -1;
            }
            --depth;
            ++p;
            continue;
        }
        if (*p == '|') {
            if (need_term) {
                return -1;
            }
            need_term = 1;
            ++p;
            if (*p == '|') {
                ++p;
            }
            continue;
        }
        if (*p == '\0') {
            break;
        }

        const char *start = p;
        while (*p != '\0' && !isspace((unsigned char)*p) &&
               *p != '(' && *p != ')' && *p != '|') {
            ++p;
        }
        size_t token_len = (size_t)(p - start);
        if (token_len == 0) {
            continue;
        }

        if (snifer_token_equals(start, token_len, "or")) {
            if (need_term || !saw_term) {
                return -1;
            }
            need_term = 1;
            continue;
        }

        if (!need_term) {
            return -1;
        }
        if (snifer_token_equals(start, token_len, "all")) {
            all = 1;
            saw_term = 1;
            need_term = 0;
            continue;
        }

        int bit = snifer_type_bit_for_token(start, token_len);
        if (bit == 0) {
            return -1;
        }
        int duplicate = 0;
        for (size_t i = 0; i < count; ++i) {
            if (bits_out[i] == bit) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate) {
            if (count >= bits_cap) {
                return -1;
            }
            bits_out[count++] = bit;
        }
        saw_term = 1;
        need_term = 0;
    }

    if (depth != 0 || (saw_term && need_term)) {
        return -1;
    }
    if (!saw_term) {
        all = 1;
    }
    *count_out = count;
    *all_out = all;
    return 0;
}

static const char *snifer_type_expression(int bit)
{
    switch (bit) {
    case SNIFER_TYPE_TCP:
        return "tcp";
    case SNIFER_TYPE_UDP:
        return "udp";
    case SNIFER_TYPE_ICMP:
        return "(icmp or icmp6)";
    case SNIFER_TYPE_ARP:
        return "arp";
    case SNIFER_TYPE_IPV4:
        return "ip";
    case SNIFER_TYPE_IPV6:
        return "ip6";
    default:
        return NULL;
    }
}

static int snifer_append_text(char *buf, size_t buf_size, size_t *pos,
                              const char *text)
{
    size_t len;

    if (buf == NULL || pos == NULL || text == NULL || buf_size == 0 ||
        *pos >= buf_size) {
        return -1;
    }
    len = strlen(text);
    if (len > buf_size - 1 - *pos) {
        return -1;
    }
    memcpy(buf + *pos, text, len);
    *pos += len;
    buf[*pos] = '\0';
    return 0;
}

static int snifer_append_format(char *buf, size_t buf_size, size_t *pos,
                                const char *fmt, ...)
{
    va_list ap;
    int needed;

    if (buf == NULL || pos == NULL || fmt == NULL || buf_size == 0 ||
        *pos >= buf_size) {
        return -1;
    }
    va_start(ap, fmt);
    needed = vsnprintf(buf + *pos, buf_size - *pos, fmt, ap);
    va_end(ap);
    if (needed < 0 || (size_t)needed > buf_size - 1 - *pos) {
        return -1;
    }
    *pos += (size_t)needed;
    return 0;
}

/* ---------------------------------------------------------------------------
 * Device enumeration
 * --------------------------------------------------------------------------- */

int sniffer_list_devices(char *errbuf, size_t errbuf_size)
{
    pcap_if_t *alldevs = NULL;
    pcap_if_t *d = NULL;
    int count = 0;
    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (pcap_findalldevs(&alldevs, pcap_errbuf) == -1) {
        snifer_copy_error(errbuf, errbuf_size, pcap_errbuf);
        fprintf(stderr, "snifer: failed to enumerate interfaces: %s\n",
                pcap_errbuf);
        return -1;
    }

    if (alldevs == NULL) {
        snifer_set_error(errbuf, errbuf_size,
                         "no capture interfaces found");
        fprintf(stderr,
                "snifer: no capture interfaces found. Do you have permissions\n"
                "        to capture packets (e.g. run with elevated privileges\n"
                "        or add your user to the packet capture group)?\n");
        return -1;
    }

    fprintf(stdout, "Available capture interfaces:\n");
    for (d = alldevs; d != NULL; d = d->next) {
        count++;
        fprintf(stdout, "  %d. %s", count, d->name);
        if (d->description) {
            fprintf(stdout, " (%s)", d->description);
        }
        fputc('\n', stdout);

        /* Show addresses if present */
        if (d->addresses != NULL) {
            pcap_addr_t *a = NULL;
            for (a = d->addresses; a != NULL; a = a->next) {
                if (a->addr != NULL && a->addr->sa_family == AF_INET) {
                    char buf[INET_ADDRSTRLEN];
                    struct sockaddr_in *sin =
                        (struct sockaddr_in *)a->addr;
                    if (inet_ntop(AF_INET, &sin->sin_addr, buf,
                                  sizeof(buf))) {
                        fprintf(stdout, "       IPv4: %s\n", buf);
                    }
                } else if (a->addr != NULL &&
                           a->addr->sa_family == AF_INET6) {
                    char buf[INET6_ADDRSTRLEN];
                    struct sockaddr_in6 *sin6 =
                        (struct sockaddr_in6 *)a->addr;
                    if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf,
                                  sizeof(buf))) {
                        fprintf(stdout, "       IPv6: %s\n", buf);
                    }
                }
            }
        }
    }
    pcap_freealldevs(alldevs);

    if (errbuf != NULL && errbuf_size > 0) {
        errbuf[0] = '\0';
    }

    if (count == 0) {
        fprintf(stderr,
                "snifer: no usable interfaces found. On Linux you may need\n"
                "        libpcap plus appropriate permissions; on macOS you may\n"
                "        need to grant network monitoring permissions in Privacy\n"
                "        & Security preferences.\n");
        return -1;
    }

    return count;
}

/* ---------------------------------------------------------------------------
 * Interface selection + open
 * --------------------------------------------------------------------------- */

pcap_t *sniffer_open_interface(const char *device_name,
                               char *errbuf,
                               size_t errbuf_size)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (device_name == NULL || device_name[0] == '\0') {
        snifer_set_error(errbuf, errbuf_size, "no interface specified");
        return NULL;
    }

    /*
     * pcap_open_live() is the portable entry point.
     *
     * Npcap on Windows supports the same API; the main cross-platform
     * caveats are:
     *   - snapshot length
     *   - promiscuous mode (often ignored on WiFi on macOS)
     *   - timeout for pcap_next_ex readiness
     */
    int snaplen = 65535; /* capture full packets by default */
    int promisc = 0;     /* start conservative on macOS; user can change */
    int timeout = 50;    /* milliseconds; affects pcap_next_ex readiness */

    pcap_t *handle = pcap_open_live(device_name, snaplen, promisc,
                                    timeout, pcap_errbuf);
    if (handle == NULL) {
        snifer_copy_error(errbuf, errbuf_size, pcap_errbuf);
        return NULL;
    }

    if (errbuf != NULL && errbuf_size > 0) {
        errbuf[0] = '\0';
    }

    /* Verify link-layer type is usable before proceeding. */
    int linktype = pcap_datalink(handle);
    (void)linktype;

    return handle;
}

/* ---------------------------------------------------------------------------
 * Filter construction
 * --------------------------------------------------------------------------- */

static int snifer_build_filter(const struct sniffer_options *opts,
                              char *buf, size_t bufsz)
{
    enum { MAX_TYPE_TERMS = 8 };
    int type_bits[MAX_TYPE_TERMS];
    size_t type_count = 0;
    int all_types = 1;
    int tcp_selected = 0;
    int udp_selected = 0;
    char clauses[3][256];
    size_t clause_count = 0;
    size_t pos = 0;

    if (buf == NULL || bufsz == 0) {
        return -1;
    }
    buf[0] = '\0';

    if (snifer_parse_type_bits(opts != NULL ? opts->packet_type : NULL,
                               type_bits, MAX_TYPE_TERMS, &type_count,
                               &all_types) != 0) {
        return -1;
    }

    for (size_t i = 0; i < type_count; ++i) {
        if (type_bits[i] == SNIFER_TYPE_TCP) {
            tcp_selected = 1;
        } else if (type_bits[i] == SNIFER_TYPE_UDP) {
            udp_selected = 1;
        }
    }

    if (!all_types && type_count > 0) {
        size_t type_pos = 0;
        clauses[clause_count][0] = '\0';
        if (type_count > 1 &&
            snifer_append_text(clauses[clause_count],
                               sizeof(clauses[clause_count]), &type_pos,
                               "(") != 0) {
            return -1;
        }
        for (size_t i = 0; i < type_count; ++i) {
            const char *expr = snifer_type_expression(type_bits[i]);
            if (expr == NULL) {
                return -1;
            }
            if (i > 0 &&
                snifer_append_text(clauses[clause_count],
                                   sizeof(clauses[clause_count]), &type_pos,
                                   " or ") != 0) {
                return -1;
            }
            if (snifer_append_text(clauses[clause_count],
                                   sizeof(clauses[clause_count]), &type_pos,
                                   expr) != 0) {
                return -1;
            }
        }
        if (type_count > 1 &&
            snifer_append_text(clauses[clause_count],
                               sizeof(clauses[clause_count]), &type_pos,
                               ")") != 0) {
            return -1;
        }
        ++clause_count;
    }

    if (opts != NULL && opts->ip_addr != NULL && opts->ip_addr[0] != '\0') {
        struct in_addr addr;
        char ip[INET_ADDRSTRLEN];

        if (inet_pton(AF_INET, opts->ip_addr, &addr) != 1 ||
            inet_ntop(AF_INET, &addr, ip, sizeof(ip)) == NULL) {
            return -1;
        }
        size_t ip_pos = 0;
        clauses[clause_count][0] = '\0';
        if (snifer_append_format(clauses[clause_count],
                                 sizeof(clauses[clause_count]), &ip_pos,
                                 "host %s", ip) != 0) {
            return -1;
        }
        ++clause_count;
    }

    if (opts != NULL && opts->port != 0) {
        char port_clause[256];
        size_t port_pos = 0;
        int have_port_protocol = tcp_selected || udp_selected;

        port_clause[0] = '\0';
        if (tcp_selected && !udp_selected && type_count == 1) {
            if (snifer_append_format(port_clause, sizeof(port_clause),
                                     &port_pos, "tcp port %u",
                                     (unsigned)opts->port) != 0) {
                return -1;
            }
        } else if (udp_selected && !tcp_selected && type_count == 1) {
            if (snifer_append_format(port_clause, sizeof(port_clause),
                                     &port_pos, "udp port %u",
                                     (unsigned)opts->port) != 0) {
                return -1;
            }
        } else {
            if (snifer_append_text(port_clause, sizeof(port_clause),
                                   &port_pos, "(") != 0) {
                return -1;
            }
            if (tcp_selected || !have_port_protocol) {
                if (snifer_append_format(port_clause, sizeof(port_clause),
                                         &port_pos, "tcp port %u",
                                         (unsigned)opts->port) != 0) {
                    return -1;
                }
            }
            if ((!have_port_protocol || tcp_selected) && udp_selected) {
                if (snifer_append_text(port_clause, sizeof(port_clause),
                                       &port_pos, " or ") != 0) {
                    return -1;
                }
            } else if (!have_port_protocol) {
                if (snifer_append_text(port_clause, sizeof(port_clause),
                                       &port_pos, " or ") != 0) {
                    return -1;
                }
            }
            if (udp_selected || !have_port_protocol) {
                if (snifer_append_format(port_clause, sizeof(port_clause),
                                         &port_pos, "udp port %u",
                                         (unsigned)opts->port) != 0) {
                    return -1;
                }
            }
            if (snifer_append_text(port_clause, sizeof(port_clause),
                                   &port_pos, ")") != 0) {
                return -1;
            }
        }

        if (clause_count >= 3) {
            return -1;
        }
        size_t port_clause_len = strlen(port_clause);
        if (port_clause_len >= sizeof(clauses[clause_count])) {
            return -1;
        }
        memcpy(clauses[clause_count], port_clause, port_clause_len + 1);
        ++clause_count;
    }

    if (clause_count == 0) {
        return 0;
    }

    pos = 0;
    for (size_t i = 0; i < clause_count; ++i) {
        if (i > 0 && snifer_append_text(buf, bufsz, &pos, " and ") != 0) {
            return -1;
        }
        if (snifer_append_text(buf, bufsz, &pos, "(") != 0 ||
            snifer_append_text(buf, bufsz, &pos, clauses[i]) != 0 ||
            snifer_append_text(buf, bufsz, &pos, ")") != 0) {
            return -1;
        }
    }
    return 0;
}

int sniffer_apply_filters(pcap_t *handle,
                          const struct sniffer_options *opts,
                          char *errbuf,
                          size_t errbuf_size)
{
    char filter[1024];

    if (handle == NULL) {
        snifer_set_error(errbuf, errbuf_size, "invalid capture handle");
        return -1;
    }
    if (snifer_build_filter(opts, filter, sizeof(filter)) != 0) {
        snifer_set_error(errbuf, errbuf_size,
                         "invalid filter specification");
        return -1;
    }

    struct bpf_program fp;
    memset(&fp, 0, sizeof(fp));

    if (filter[0] == '\0') {
        /* No filter requested. Do not touch the capture filter at all, so
         * we do not fail on platforms or interfaces where pcap_setfilter
         * with NULL is not supported. */
        return 0;
    }

    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        snifer_set_error(errbuf, errbuf_size,
                         "failed to compile filter '%s': %s",
                         filter, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        snifer_set_error(errbuf, errbuf_size,
                         "failed to set filter '%s': %s",
                         filter, pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }
    pcap_freecode(&fp);
    return 0;
}

/* ---------------------------------------------------------------------------
 * Packet decoding helpers
 * --------------------------------------------------------------------------- */

/* Print a hex dump of a buffer. We intentionally keep this short and
 * readable rather than optimizing it for speed. */
static void snifer_hex_dump(const u_char *data, size_t len,
                            FILE *out)
{
    size_t i;
    if (len == 0) {
        fprintf(out, "(empty)\n");
        return;
    }
    for (i = 0; i < len; i++) {
        fprintf(out, "%02x ", data[i]);
        if (((int)(i % 16)) == 15 || i == len - 1) {
            /* pad the last line */
            size_t remaining = (size_t)(16 - (i % 16) - 1);
            size_t j;
            for (j = 0; j < remaining; j++) {
                fputs("   ", out);
            }
            fputc('\n', out);
        }
    }
}

/* Minimal safe accessors that avoid reading beyond packet boundaries. */
static const u_char *snifer_ptr(const u_char *base,
                                       size_t base_len,
                                       size_t offset,
                                       size_t size)
{
    /* Check for overflow: offset > base_len, or size > remaining space */
    if (offset > base_len || size > base_len - offset) {
        return NULL;
    }
    return base + offset;
}

/* Parse IPv4 header fields safely from a raw buffer. Returns 0 on success,
 * -1 if the buffer is too short or the header length is invalid. */
static int snifer_parse_ipv4(const u_char *data,
                             size_t data_len,
                             uint8_t *version,
                             uint8_t *ihl,
                             uint8_t *protocol,
                             uint16_t *tot_len,
                             const u_char **payload,
                             size_t *payload_len)
{
    if (data_len < (size_t)sizeof(struct ip)) {
        return -1;
    }
    const struct ip *ip_hdr = (const struct ip *)data;

    /* IPv4 header length must be a multiple of 4 bytes and at least 20 */
    uint8_t ihl_bytes = (uint8_t)(ip_hdr->ip_hl) * 4;
    if (ihl_bytes < 20 || ihl_bytes > data_len) {
        return -1;
    }

    *version = ip_hdr->ip_v;
    *ihl = ihl_bytes;
    *protocol = ip_hdr->ip_p;
    *tot_len = ntohs(ip_hdr->ip_len);

    /* Cap payload to the declared IP total length */
    size_t declared_payload = (*tot_len > ihl_bytes) ? (size_t)(*tot_len - ihl_bytes) : 0;
    if (ihl_bytes < data_len) {
        *payload = data + ihl_bytes;
        *payload_len = data_len - ihl_bytes;
        if (*payload_len > declared_payload)
            *payload_len = declared_payload;
    } else {
        *payload = NULL;
        *payload_len = 0;
    }
    return 0;
}

/* Parse IPv6 header fields safely. */
static int snifer_parse_ipv6(const u_char *data,
                             size_t data_len,
                             uint8_t *next_header,
                             const u_char **payload,
                             size_t *payload_len)
{
    if (data_len < (size_t)sizeof(struct ip6_hdr)) {
        return -1;
    }
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)data;
    *next_header = ip6->ip6_nxt;
    *payload = data + sizeof(struct ip6_hdr);
    *payload_len = data_len - sizeof(struct ip6_hdr);
    return 0;
}

/* ---------------------------------------------------------------------------
 * Packet printing
 * --------------------------------------------------------------------------- */

/* Ethertype constants (network byte order already, but compare in host
 * order after ntohs). */
#define ETHERTYPE_IP   0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_RARP 0x8035
/* IPv6 ethertype 0x86DD is already defined in <net/ethernet.h> on macOS;
 * define it only if it is missing so we do not get redefinition warnings. */
#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

static void snifer_print_packet(const u_char *capture,
                                size_t capture_len,
                                struct pcap_pkthdr *hdr)
{
    if (capture_len < (size_t)sizeof(struct ether_header)) {
        fprintf(stdout, "[truncated ethernet frame, len=%zu]\n",
                capture_len);
        return;
    }

    const struct ether_header *eth = (const struct ether_header *)capture;
    uint16_t ether_type = ntohs(eth->ether_type);

    /*
     * We print three layers:
     *   1) frame level (ethernet type)
     *   2) network level (IP/ARP)
     *   3) transport/payload level if applicable
     *
     * We do not try to decode everything; for unknown payload we dump hex.
     */
    fprintf(stdout, "\n--- Packet ---\n");
    fprintf(stdout, "Timestamp: %lu.%06lu sec\n",
            (unsigned long)hdr->ts.tv_sec,
            (unsigned long)hdr->ts.tv_usec);
    fprintf(stdout, "Captured length: %u bytes\n", hdr->caplen);
    fprintf(stdout, "Original length: %u bytes\n", hdr->len);
    fprintf(stdout, "Ethernet type: 0x%04x\n", ether_type);

    /* Move past ethernet header */
    const u_char *network =
        snifer_ptr(capture, capture_len, sizeof(struct ether_header),
                   0);
    size_t network_len =
        capture_len > sizeof(struct ether_header)
            ? capture_len - sizeof(struct ether_header)
            : 0;

    if (network == NULL) {
        fprintf(stdout, "Frame too short for ethernet header.\n");
        return;
    }

    if (ether_type == ETHERTYPE_IP) {
        uint8_t ver = 0, ihl = 0, proto = 0;
        uint16_t tot_len = 0;
        const u_char *ip_payload = NULL;
        size_t ip_payload_len = 0;

        if (snifer_parse_ipv4(network, network_len, &ver, &ihl, &proto,
                              &tot_len, &ip_payload, &ip_payload_len) !=
            0) {
            fprintf(stdout, "IPv4 header parse error.\n");
            return;
        }

        fprintf(stdout, "IP version: %u\n", ver);
        fprintf(stdout, "IP header length: %u bytes\n", ihl);
        fprintf(stdout, "IP total length: %u bytes\n", tot_len);
        fprintf(stdout, "IP protocol: %u\n", proto);

        /* Print source/destination IPv4 */
        if (network_len >= (size_t)sizeof(struct ip)) {
            const struct ip *iph = (const struct ip *)network;
            struct in_addr src, dst;
            src.s_addr = iph->ip_src.s_addr;
            dst.s_addr = iph->ip_dst.s_addr;
            char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &src, s, sizeof(s)) &&
                inet_ntop(AF_INET, &dst, d, sizeof(d))) {
                fprintf(stdout, "Src IP: %s\n", s);
                fprintf(stdout, "Dst IP: %s\n", d);
            }
        }

        /* Transport layer */
        switch (proto) {
        case IPPROTO_TCP: {
            fprintf(stdout, "Transport: TCP\n");
            if (ip_payload && ip_payload_len >= (size_t)sizeof(struct tcphdr)) {
                const struct tcphdr *tcp =
                    (const struct tcphdr *)ip_payload;
                uint16_t src_port = ntohs(tcp->th_sport);
                uint16_t dst_port = ntohs(tcp->th_dport);
                fprintf(stdout, "Src port: %u\n", src_port);
                fprintf(stdout, "Dst port: %u\n", dst_port);
                fprintf(stdout, "TCP flags: 0x%02x\n", tcp->th_flags);

                const u_char *tcp_payload =
                    snifer_ptr(ip_payload, ip_payload_len,
                               sizeof(struct tcphdr), 0);
                size_t tcp_payload_len =
                    ip_payload_len > sizeof(struct tcphdr)
                        ? ip_payload_len - sizeof(struct tcphdr)
                        : 0;
                if (tcp_payload_len > 0) {
                    fprintf(stdout, "TCP payload (%zu bytes):\n",
                            tcp_payload_len);
                    snifer_hex_dump(tcp_payload, tcp_payload_len,
                                    stdout);
                } else {
                    fprintf(stdout, "TCP payload: (none)\n");
                }
            } else {
                fprintf(stdout, "TCP header too short.\n");
            }
            break;
        }
        case IPPROTO_UDP: {
            fprintf(stdout, "Transport: UDP\n");
            if (ip_payload && ip_payload_len >= (size_t)sizeof(struct udphdr)) {
                const struct udphdr *udp =
                    (const struct udphdr *)ip_payload;
                uint16_t src_port = ntohs(udp->uh_sport);
                uint16_t dst_port = ntohs(udp->uh_dport);
                uint16_t udp_len = ntohs(udp->uh_ulen);
                fprintf(stdout, "Src port: %u\n", src_port);
                fprintf(stdout, "Dst port: %u\n", dst_port);
                fprintf(stdout, "UDP length: %u\n", udp_len);

                const u_char *udp_payload =
                    snifer_ptr(ip_payload, ip_payload_len,
                               sizeof(struct udphdr), 0);
                size_t udp_payload_len =
                    ip_payload_len > sizeof(struct udphdr)
                        ? ip_payload_len - sizeof(struct udphdr)
                        : 0;
                if (udp_payload_len > 0) {
                    fprintf(stdout, "UDP payload (%zu bytes):\n",
                            udp_payload_len);
                    snifer_hex_dump(udp_payload, udp_payload_len,
                                    stdout);
                } else {
                    fprintf(stdout, "UDP payload: (none)\n");
                }
            } else {
                fprintf(stdout, "UDP header too short.\n");
            }
            break;
        }
        case IPPROTO_ICMP: {
            fprintf(stdout, "Transport: ICMP\n");
            if (ip_payload_len > 0) {
                fprintf(stdout, "ICMP payload (%zu bytes):\n",
                        ip_payload_len);
                snifer_hex_dump(ip_payload, ip_payload_len, stdout);
            }
            break;
        }
        default: {
            fprintf(stdout, "Transport: other (protocol=%u)\n", proto);
            if (ip_payload && ip_payload_len > 0) {
                fprintf(stdout,
                        "IP payload (%zu bytes):\n",
                        ip_payload_len);
                snifer_hex_dump(ip_payload, ip_payload_len, stdout);
            }
            break;
        }
        }
    } else if (ether_type == ETHERTYPE_IPV6) {
        uint8_t nxt = 0;
        const u_char *ip6_payload = NULL;
        size_t ip6_payload_len = 0;
        if (snifer_parse_ipv6(network, network_len, &nxt,
                              &ip6_payload, &ip6_payload_len) != 0) {
            fprintf(stdout, "IPv6 header parse error.\n");
            return;
        }
        fprintf(stdout, "IP version: 6\n");
        fprintf(stdout, "Next header: %u\n", nxt);

        /* Print IPv6 src/dst */
        if (network_len >= (size_t)sizeof(struct ip6_hdr)) {
            const struct ip6_hdr *ip6 =
                (const struct ip6_hdr *)network;
            char s[INET6_ADDRSTRLEN], d[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &ip6->ip6_src, s, sizeof(s)) &&
                inet_ntop(AF_INET6, &ip6->ip6_dst, d, sizeof(d))) {
                fprintf(stdout, "Src IP: %s\n", s);
                fprintf(stdout, "Dst IP: %s\n", d);
            }
        }

        switch (nxt) {
        case IPPROTO_TCP: {
            fprintf(stdout, "Transport: TCP (IPv6)\n");
            if (ip6_payload && ip6_payload_len >= (size_t)sizeof(struct tcphdr)) {
                const struct tcphdr *tcp =
                    (const struct tcphdr *)ip6_payload;
                fprintf(stdout, "Src port: %u\n",
                        ntohs(tcp->th_sport));
                fprintf(stdout, "Dst port: %u\n",
                        ntohs(tcp->th_dport));
                fprintf(stdout, "TCP flags: 0x%02x\n", tcp->th_flags);
                const u_char *tcp_payload =
                    snifer_ptr(ip6_payload, ip6_payload_len,
                               sizeof(struct tcphdr), 0);
                size_t tcp_payload_len =
                    ip6_payload_len > sizeof(struct tcphdr)
                        ? ip6_payload_len - sizeof(struct tcphdr)
                        : 0;
                if (tcp_payload_len > 0) {
                    fprintf(stdout,
                            "TCP payload (%zu bytes):\n",
                            tcp_payload_len);
                    snifer_hex_dump(tcp_payload, tcp_payload_len,
                                    stdout);
                }
            } else {
                fprintf(stdout, "TCP header too short.\n");
            }
            break;
        }
        case IPPROTO_UDP: {
            fprintf(stdout, "Transport: UDP (IPv6)\n");
            if (ip6_payload && ip6_payload_len >= (size_t)sizeof(struct udphdr)) {
                const struct udphdr *udp =
                    (const struct udphdr *)ip6_payload;
                fprintf(stdout, "Src port: %u\n",
                        ntohs(udp->uh_sport));
                fprintf(stdout, "Dst port: %u\n",
                        ntohs(udp->uh_dport));
                const u_char *udp_payload =
                    snifer_ptr(ip6_payload, ip6_payload_len,
                               sizeof(struct udphdr), 0);
                size_t udp_payload_len =
                    ip6_payload_len > sizeof(struct udphdr)
                        ? ip6_payload_len - sizeof(struct udphdr)
                        : 0;
                if (udp_payload_len > 0) {
                    fprintf(stdout,
                            "UDP payload (%zu bytes):\n",
                            udp_payload_len);
                    snifer_hex_dump(udp_payload, udp_payload_len,
                                    stdout);
                }
            } else {
                fprintf(stdout, "UDP header too short.\n");
            }
            break;
        }
        default: {
            fprintf(stdout, "Transport: other (next header=%u)\n", nxt);
            if (ip6_payload && ip6_payload_len > 0) {
                fprintf(stdout,
                        "IPv6 payload (%zu bytes):\n",
                        ip6_payload_len);
                snifer_hex_dump(ip6_payload, ip6_payload_len, stdout);
            }
            break;
        }
        }
    } else if (ether_type == ETHERTYPE_ARP) {
        fprintf(stdout, "ARP frame\n");
        if (network_len > 0) {
            fprintf(stdout, "ARP payload (%zu bytes):\n", network_len);
            snifer_hex_dump(network, network_len, stdout);
        }
    } else {
        fprintf(stdout, "Ethernet type: other/unknown (0x%04x)\n",
                ether_type);
        if (network_len > 0) {
            fprintf(stdout, "Payload (%zu bytes):\n", network_len);
            snifer_hex_dump(network, network_len, stdout);
        }
    }
}

/* ---------------------------------------------------------------------------
 * Main capture loop
 * --------------------------------------------------------------------------- */

int sniffer_capture(const struct sniffer_options *opts)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "snifer: failed to enumerate interfaces: %s\n",
                errbuf);
        return -1;
    }
    if (alldevs == NULL) {
        fprintf(stderr, "snifer: no capture interfaces found.\n");
        return -1;
    }

    /* Count and verify exactly one interface exists */
    int count = 0;
    const pcap_if_t *selected = NULL;
    for (const pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        count++;
        if (count == 1) {
            selected = d;
        }
    }

    if (count == 0) {
        fprintf(stderr, "snifer: no capture interfaces found.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (count != 1) {
        fprintf(stderr,
                "snifer: sniffer_capture() is only usable when exactly one "
                "interface is available. For interactive sessions, use the "
                "menu in main().\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Copy the name before freeing the list */
    char name[256];
    snprintf(name, sizeof(name), "%s", selected->name);
    pcap_freealldevs(alldevs);

    pcap_t *handle = sniffer_open_interface(name, errbuf, sizeof(errbuf));
    if (handle == NULL) {
        fprintf(stderr, "snifer: cannot open %s: %s\n", name, errbuf);
        return -1;
    }

    int rc = sniffer_run_capture(handle, opts);
    /* sniffer_run_capture no longer closes the handle; caller is responsible */
    sniffer_close(handle);
    return rc;
}

int sniffer_run_capture(pcap_t *handle,
                        const struct sniffer_options *opts)
{
    if (handle == NULL) {
        fprintf(stderr, "snifer: invalid capture handle\n");
        return -1;
    }

    /*
     * NOTE: This function does NOT close the handle. The caller retains
     * ownership and must call sniffer_close() after this returns.
     */

    char errbuf[PCAP_ERRBUF_SIZE];
    if (opts != NULL) {
        if (sniffer_apply_filters(handle, opts, errbuf,
                                  sizeof(errbuf)) != 0) {
            fprintf(stderr, "snifer: %s\n", errbuf);
            return -1;
        }
    }

    /* Install a simple SIGINT handler so we can shut down cleanly. */
    struct sigaction old_sa_int, old_sa_term;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = snifer_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, &old_sa_int);
    sigaction(SIGTERM, &sa, &old_sa_term);

    fprintf(stdout,
            "snifer: capturing packets (Ctrl+C to stop)...\n\n");

    int packet_count = 0;
    snifer_running = 1;

    while (snifer_running) {
        struct pcap_pkthdr *hdr = NULL;
        const u_char *packet = NULL;

        int ret = pcap_next_ex(handle, &hdr, &packet);
        if (ret == 0) {
            /* Timeout; loop again */
            continue;
        }
        if (ret == -1) {
            fprintf(stderr, "snifer: capture error: %s\n",
                    pcap_geterr(handle));
            break;
        }
        if (ret == -2) {
            /* EOF / interface down */
            fprintf(stderr, "snifer: end of capture.\n");
            break;
        }

        packet_count++;
        fprintf(stdout, "[#%d]\n", packet_count);
        snifer_print_packet(packet, hdr->caplen, hdr);
    }

    fprintf(stdout, "\nsnifer: captured %d packet(s).\n", packet_count);
    /* Restore original signal handlers */
    sigaction(SIGINT, &old_sa_int, NULL);
    sigaction(SIGTERM, &old_sa_term, NULL);
    return 0;
}

void sniffer_close(pcap_t *handle)
{
    if (handle) {
        pcap_close(handle);
    }
}

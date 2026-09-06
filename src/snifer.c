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

/* Quiet stdout/stderr buffering so the menu and capture output don't get
 * interleaved in odd ways. */


static int snifer_strtolower(char *dst, const char *src, size_t n)
{
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; ++i) {
        dst[i] = (char)tolower((unsigned char)src[i]);
    }
    dst[i] = '\0';
    return (int)i;
}

/* Normalize a type string for comparison: "tcp" -> "tcp", "TCP" -> "tcp",
 * whitespace trimmed, no prefix/suffix surprises. */
static int snifer_parse_packet_type(const char *input, char *out, size_t out_size)
{
    char tmp[64];
    if (input == NULL) {
        out[0] = '\0';
        return 0;
    }
    size_t len = strnlen(input, sizeof(tmp) - 1);
    if (len == 0 || len >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, input, len);
    tmp[len] = '\0';

    /* trim leading whitespace */
    char *p = tmp;
    while (*p && isspace((unsigned char)*p)) ++p;

    /* trim trailing whitespace */
    char *end = p + strnlen(p, sizeof(tmp));
    while (end > p && isspace((unsigned char)*(end - 1))) --end;
    *end = '\0';

    if (*p == '\0') {
        out[0] = '\0';
        return 0;
    }

    snifer_strtolower(out, p, out_size);
    return 0;
}

/* ---------------------------------------------------------------------------
 * Device enumeration
 * --------------------------------------------------------------------------- */

int sniffer_list_devices(char *errbuf, size_t errbuf_size)
{
    (void)errbuf_size;
    pcap_if_t *alldevs = NULL;
    pcap_if_t *d = NULL;
    int count = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "snifer: failed to enumerate interfaces: %s\n",
                errbuf);
        return -1;
    }

    if (alldevs == NULL) {
        fprintf(stderr,
                "snifer: no capture interfaces found. Do you have permissions\n"
                "        to capture packets (e.g. run with elevated privileges\n"
                "        or add your user to the packet capture group)?\n");
        pcap_freealldevs(alldevs);
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
    if (device_name == NULL || device_name[0] == '\0') {
        snprintf(errbuf, errbuf_size,
                 "no interface specified");
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
                                    timeout, errbuf);
    if (handle == NULL) {
        return NULL;
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
    char type[64] = {0};
    if (snifer_parse_packet_type(opts->packet_type, type, sizeof(type)) !=
        0) {
        return -1;
    }

    /*
     * We build a single pcap filter expression where practical.
     *
     * pcap filter syntax is documented at:
     *   https://www.tcpdump.org/manpages/pcap-filter.7.html
     *
     * Notes on portability:
     *   - "ether proto", "ip", "tcp", "udp", "icmp" are widely supported.
     *   - IPv6 filters ("ip6") are supported on modern libpcap/Npcap.
     *   - ARP is common but syntax can vary slightly between platforms.
     *     We handle ARP via a separate code path when needed.
     */
    enum { MAX_FILTER = 1024 };
    char parts[8][MAX_FILTER];
    int nparts = 0;

    if (opts->packet_type != NULL && type[0] != '\0') {
        if (strcmp(type, "all") == 0) {
            /* nothing to add */
        } else if (strcmp(type, "tcp") == 0) {
            snprintf(parts[nparts], MAX_FILTER, "tcp");
            nparts++;
        } else if (strcmp(type, "udp") == 0) {
            snprintf(parts[nparts], MAX_FILTER, "udp");
            nparts++;
        } else if (strcmp(type, "icmp") == 0) {
            snprintf(parts[nparts], MAX_FILTER, "icmp or icmp6");
            nparts++;
        } else if (strcmp(type, "arp") == 0) {
            /* ARP is not IP-based; keep separate */
            snprintf(parts[nparts], MAX_FILTER, "arp");
            nparts++;
        } else if (strcmp(type, "ipv4") == 0) {
            snprintf(parts[nparts], MAX_FILTER, "ip");
            nparts++;
        } else if (strcmp(type, "ipv6") == 0) {
            snprintf(parts[nparts], MAX_FILTER, "ip6");
            nparts++;
        } else {
            /* Unknown literal: treat as a raw pcap expression if it
             * contains operator characters; otherwise reject. */
            if (strpbrk(type, "&=|~()!")) {
                snprintf(parts[nparts], MAX_FILTER, "%s", type);
                nparts++;
            } else {
                return -1;
            }
        }
    }

    if (opts->ip_addr != NULL && opts->ip_addr[0] != '\0') {
        /* Use inet_pton to validate and build the filter. We only support
         * IPv4 here for simplicity. */
        struct in_addr addr;
        if (inet_pton(AF_INET, opts->ip_addr, &addr) != 1) {
            return -1;
        }
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip, sizeof(ip));
        snprintf(parts[nparts], MAX_FILTER, "(host %s)", ip);
        nparts++;
    }

    if (opts->port != 0) {
        char port[32];
        snprintf(port, sizeof(port), "%u", (unsigned)opts->port);
        /*
         * In pcap filter syntax, `port` implies tcp or udp depending on
         * context, but to be explicit and predictable we match both.
         * This is still efficient because the kernel BPF filters early.
         */
        snprintf(parts[nparts], MAX_FILTER, "(tcp port %s or udp port %s)",
                 port, port);
        nparts++;
    }

    if (nparts == 0) {
        buf[0] = '\0';
        return 0;
    }

    buf[0] = '\0';
    size_t pos = 0;
    for (int i = 0; i < nparts; i++) {
        if (i > 0) {
            if (pos < bufsz - 1)
                buf[pos++] = ' ';
            if (pos < bufsz - 1)
                buf[pos++] = '(';
        }
        size_t len = strnlen(parts[i], MAX_FILTER);
        if (pos + len < bufsz) {
            memcpy(buf + pos, parts[i], len);
            pos += len;
        }
        if (i > 0) {
            if (pos < bufsz - 1)
                buf[pos++] = ')';
        }
    }
    buf[pos] = '\0';
    return 0;
}

int sniffer_apply_filters(pcap_t *handle,
                          const struct sniffer_options *opts,
                          char *errbuf,
                          size_t errbuf_size)
{
    char filter[1024];
    if (snifer_build_filter(opts, filter, sizeof(filter)) != 0) {
        snprintf(errbuf, errbuf_size,
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
        snprintf(errbuf, errbuf_size,
                 "failed to compile filter '%s': %s",
                 filter, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        snprintf(errbuf, errbuf_size,
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
    if (base_len < offset + size) {
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
    if (ihl_bytes < 20 || ihl_bytes > (uint8_t)(data_len)) {
        return -1;
    }

    *version = ip_hdr->ip_v;
    *ihl = ihl_bytes;
    *protocol = ip_hdr->ip_p;
    *tot_len = ntohs(ip_hdr->ip_len);

    if (ihl_bytes < data_len) {
        *payload = data + ihl_bytes;
        *payload_len = data_len - ihl_bytes;
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
    pcap_if_t *selected = NULL;
    int count = 0;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "snifer: failed to enumerate interfaces: %s\n",
                errbuf);
        return -1;
    }
    if (alldevs == NULL) {
        fprintf(stderr, "snifer: no capture interfaces found.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for (const pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        count++;
    }
    pcap_freealldevs(alldevs);

    if (count == 0) {
        fprintf(stderr, "snifer: no capture interfaces found.\n");
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

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return -1;
    }
    selected = alldevs;
    pcap_freealldevs(alldevs);

    pcap_t *handle = sniffer_open_interface(selected->name, errbuf,
                                            sizeof(errbuf));
    if (handle == NULL) {
        fprintf(stderr, "snifer: cannot open %s: %s\n",
                selected->name, errbuf);
        return -1;
    }

    return sniffer_run_capture(handle, opts);
}

int sniffer_run_capture(pcap_t *handle,
                        const struct sniffer_options *opts)
{
    if (handle == NULL) {
        fprintf(stderr, "snifer: invalid capture handle\n");
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    if (opts != NULL) {
        if (sniffer_apply_filters(handle, opts, errbuf,
                                  sizeof(errbuf)) != 0) {
            fprintf(stderr, "snifer: %s\n", errbuf);
            pcap_close(handle);
            return -1;
        }
    }

    /* Install a simple SIGINT handler so we can shut down cleanly. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = snifer_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    fprintf(stdout,
            "snifer: capturing packets (Ctrl+C to stop)...\n\n");

    int packet_count = 0;

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
    pcap_close(handle);
    return 0;
}

void sniffer_close(pcap_t *handle)
{
    if (handle) {
        pcap_close(handle);
    }
}

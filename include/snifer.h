#ifndef SNIFER_H
#define SNIFER_H

#include <pcap/pcap.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * sniffer_options - user-supplied capture constraints.
 *
 * Use 0/NULL to mean "unconstrained". Port filter applies to TCP/UDP
 * source or destination ports.
 */
struct sniffer_options {
    /* Packet type filter: "all", "tcp", "udp", "icmp", "arp", or NULL
     * for "all". Exact matching is case-insensitive where applicable. */
    const char *packet_type;

    /* Optional IP filter, e.g. "192.168.1.5". If non-NULL, only packets
     * involving this IPv4 address (src or dst) are reported. */
    const char *ip_addr;

    /* Optional port filter, e.g. 80. If non-zero, only TCP/UDP packets
     * where src or dst port matches are reported. */
    unsigned short port;

    /* Maximum interface MTU to use when constructing a pcap filter. Most
     * common networks use 1500; set higher if needed. */
    int snaplen;
};

/**
 * sniffer_init - discover and open the best available capture interface.
 *
 * Returns NULL on failure and sets errbuf with a human-readable message.
 * The caller must free the returned handle with sniffer_close().
 */
pcap_t *sniffer_init(int *dev_idx_out, char *errbuf, size_t errbuf_size);

/**
 * sniffer_list_devices - print available capture interfaces to stdout.
 * Returns the number of interfaces enumerated, or -1 on error.
 */
int sniffer_list_devices(char *errbuf, size_t errbuf_size);

/**
 * sniffer_apply_filters - compile and apply a pcap filter for the given
 * options. Returns 0 on success, -1 on error (error text in errbuf).
 */
int sniffer_apply_filters(pcap_t *handle,
                          const struct sniffer_options *opts,
                          char *errbuf,
                          size_t errbuf_size);

/**
 * sniffer_capture - run a live capture session using sniffer_options.
 *
 * This blocks until the session is interrupted (Ctrl+C) or an error occurs.
 * Snapshot output is printed to stdout.
 *
 * Returns 0 on clean exit, -1 on fatal error.
 */
int sniffer_capture(const struct sniffer_options *opts);

/**
 * sniffer_close - free resources associated with a handle opened by
 * sniffer_init().
 */
void sniffer_close(pcap_t *handle);

#endif /* SNIFER_H */

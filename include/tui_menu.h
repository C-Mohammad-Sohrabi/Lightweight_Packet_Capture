#ifndef TUI_MENU_H
#define TUI_MENU_H

#include <pcap/pcap.h>
#include <stddef.h>

#include "snifer.h"

/**
 * menu_result - outcome of a menu session.
 */
enum menu_result {
    MENU_RESULT_CAPTURE = 0,   /* user confirmed and should capture */
    MENU_RESULT_CANCEL = 1,    /* user cancelled the setup */
    MENU_RESULT_ERROR = -1     /* fatal UI or input error */
};

/**
 * menu_capture_setup - interactive ncurses TUI to choose:
 *   - capture interface
 *   - packet type(s)
 *   - optional IPv4 filter
 *   - optional TCP/UDP port filter
 *
 * On success, dev_out, opts_out, errbuf, and errbuf_size are filled in and
 * the function returns MENU_RESULT_CAPTURE.
 *
 * The caller is responsible for opening the interface named in *dev_out and
 * for freeing *opts_out fields if needed.
 */
enum menu_result menu_capture_setup(pcap_if_t *alldevs,
                                   const char **dev_out,
                                   struct sniffer_options *opts_out,
                                   char *errbuf,
                                   size_t errbuf_size);
// Note: sniffer_options is defined in snifer.h

#endif /* TUI_MENU_H */

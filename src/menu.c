/*
 * menu.c - ncurses TUI for interactive capture setup (menuconfig)
 *
 * Uses only the core ncurses library (no separate menu/form libraries).
 * Provides a clean five-step workflow:
 *   1) Select interface
 *   2) Select packet type(s)
 *   3) Optional IPv4 filter
 *   4) Optional port filter
 *   5) Confirm and start capture
 */

#include "tui_menu.h"
#include "snifer.h"

#include <ncurses.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* ---------------------------------------------------------------------------
 * Minimum terminal size
 * --------------------------------------------------------------------------- */
#define MIN_LINES 16
#define MIN_COLS  50

/* ---------------------------------------------------------------------------
 * Color pair indices
 * --------------------------------------------------------------------------- */
#define CP_HEADER    1
#define CP_HIGHLIGHT 2

/* ---------------------------------------------------------------------------
 * Init / cleanup
 * --------------------------------------------------------------------------- */
static int tui_init(void)
{
    if (initscr() == NULL)
        return -1;
    if (has_colors()) {
        start_color();
        init_pair(CP_HEADER,    COLOR_WHITE, COLOR_BLUE);
        init_pair(CP_HIGHLIGHT, COLOR_BLACK, COLOR_CYAN);
    }
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    return 0;
}

static void tui_done(void)
{
    curs_set(1);
    echo();
    endwin();
}

/* ---------------------------------------------------------------------------
 * Draw a centered title bar
 * --------------------------------------------------------------------------- */
static void draw_header(const char *title)
{
    attron(A_BOLD);
    if (has_colors()) attron(COLOR_PAIR(CP_HEADER) | A_REVERSE);
    move(0, 0);
    for (int i = 0; i < COLS; i++)
        addch(' ');
    mvaddstr(0, (COLS - (int)strlen(title)) / 2, title);
    if (has_colors()) attroff(COLOR_PAIR(CP_HEADER) | A_REVERSE);
    attroff(A_BOLD);
}

/* ---------------------------------------------------------------------------
 * Draw a status line at the bottom
 * --------------------------------------------------------------------------- */
static void draw_status(const char *text)
{
    attron(A_REVERSE);
    move(LINES - 1, 0);
    for (int i = 0; i < COLS; i++)
        addch(' ');
    mvaddstr(LINES - 1, 1, text);
    attroff(A_REVERSE);
}

/* ---------------------------------------------------------------------------
 * 1) Interface selection
 * --------------------------------------------------------------------------- */
static enum menu_result select_interface(pcap_if_t *alldevs,
                                        const char **dev_out)
{
    int count = 0;
    for (pcap_if_t *d = alldevs; d; d = d->next)
        count++;

    if (count == 0) {
        draw_status("No capture interfaces found. Press any key...");
        getch();
        return MENU_RESULT_ERROR;
    }

    if (count == 1) {
        *dev_out = alldevs->name;
        return MENU_RESULT_CAPTURE;
    }

    int max_visible = LINES - 4;
    if (max_visible < 1) max_visible = 1;
    if (max_visible > count) max_visible = count;

    int cursor = 0;
    int scroll = 0;
    int ch;

   do {
       draw_header("Select Capture Interface");
       int idx = 0;
       int y = 2;
       for (pcap_if_t *d = alldevs; d; d = d->next, idx++) {
           if (idx < scroll || idx >= scroll + max_visible)
               continue;
            if (y >= LINES - 2) break;
           if (idx == cursor) {
               if (has_colors()) attron(COLOR_PAIR(CP_HIGHLIGHT));
               else attron(A_REVERSE);
           }
           mvprintw(y, 2, " %s", d->name);
           if (d->description)
               printw("  (%s)", d->description);
           if (idx == cursor) {
               if (has_colors()) attroff(COLOR_PAIR(CP_HIGHLIGHT));
               else attroff(A_REVERSE);
           }
           y++;
           /* Show IP addresses */
           if (d->addresses) {
               for (pcap_addr_t *a = d->addresses; a; a = a->next) {
                   if (!a->addr) continue;
                   if (a->addr->sa_family == AF_INET) {
                       char buf[INET_ADDRSTRLEN];
                       struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                       if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
                           mvprintw(y, 4, "IPv4: %s", buf);
                           y++;
                       }
                   } else if (a->addr->sa_family == AF_INET6) {
                       char buf[INET6_ADDRSTRLEN];
                       struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)a->addr;
                       if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf))) {
                           mvprintw(y, 4, "IPv6: %s", buf);
                           y++;
                       }
               }
           }
        }
        }
        /* Clear rest of list area */
        for (int i = y; i < LINES - 1; i++) {
            move(i, 0);
            clrtoeol();
        }

        if (count > max_visible)
            draw_status("Up/Down: navigate  Enter: select  q: cancel  (scroll)");
        else
            draw_status("Up/Down: navigate  Enter: select  q: cancel");

        ch = getch();
        switch (ch) {
        case KEY_UP:
            if (cursor > 0) cursor--;
            if (cursor < scroll) scroll--;
            break;
        case KEY_DOWN:
            if (cursor < count - 1) cursor++;
            if (cursor >= scroll + max_visible) scroll++;
            break;
        case 'q':
        case 'Q':
        case 27:
            return MENU_RESULT_CANCEL;
        case '\n':
        case KEY_ENTER:
        case 13: {
            int idx = 0;
            for (pcap_if_t *d = alldevs; d; d = d->next, idx++) {
                if (idx == cursor) {
                    *dev_out = d->name;
                    return MENU_RESULT_CAPTURE;
                }
            }
            return MENU_RESULT_ERROR;
            }
        }
    } while (1);
}

/* ---------------------------------------------------------------------------
 * 2) Packet type selection (checklist with space to toggle)
 * --------------------------------------------------------------------------- */
typedef struct {
    const char *type;
    const char *label;
} ptype_t;

static const ptype_t types[] = {
    {"tcp",  "TCP"},
    {"udp",  "UDP"},
    {"icmp", "ICMP / ICMPv6"},
    {"arp",  "ARP"},
    {"ipv4", "IPv4"},
    {"ipv6", "IPv6"},
    {NULL, NULL}
};
static const int ntypes = 6;

static enum menu_result select_packet_types(struct sniffer_options *opts)
{
    int sel[6] = {0};
    int cursor = 0;
    int ch;

    do {
        draw_header("Select Packet Types");
        int y = 2;
        for (int i = 0; i < ntypes; i++) {
            if (i == cursor) {
                if (has_colors()) attron(COLOR_PAIR(CP_HIGHLIGHT));
                else attron(A_REVERSE);
            }
            mvprintw(y, 4, "[%c]  %s", sel[i] ? 'X' : ' ', types[i].label);
            if (i == cursor) {
                if (has_colors()) attroff(COLOR_PAIR(CP_HIGHLIGHT));
                else attroff(A_REVERSE);
            }
            y++;
        }
        /* Clear rest */
        for (int i = y; i < LINES - 1; i++) {
            move(i, 0); clrtoeol();
        }

        mvprintw(y + 1, 2, "Select one or more. If none selected, all types are captured.");
        draw_status("Up/Down: navigate  Space: toggle  Enter: done  q: cancel");

        ch = getch();
        switch (ch) {
        case KEY_UP:
            if (cursor > 0) cursor--;
            break;
        case KEY_DOWN:
            if (cursor < ntypes - 1) cursor++;
            break;
        case ' ':
            sel[cursor] = !sel[cursor];
            break;
        case 'q':
        case 'Q':
        case 27:
            return MENU_RESULT_CANCEL;
        case '\n':
        case KEY_ENTER:
        case 13: {
            int nsel = 0;
            for (int i = 0; i < ntypes; i++)
                if (sel[i]) nsel++;

            if (nsel == 0) {
                opts->packet_type = strdup("all");
                if (!opts->packet_type) return MENU_RESULT_ERROR;
                return MENU_RESULT_CAPTURE;
            }
            if (nsel == 1) {
                for (int i = 0; i < ntypes; i++) {
                    if (sel[i]) {
                        opts->packet_type = strdup(types[i].type);
                        if (!opts->packet_type) return MENU_RESULT_ERROR;
                        return MENU_RESULT_CAPTURE;
                    }
                }
            }

            /* Multiple: build "or" expression */
            size_t len = 2;
            for (int i = 0; i < ntypes; i++)
                if (sel[i]) len += strlen(types[i].type) + 4;
            char *expr = malloc(len);
            if (!expr) return MENU_RESULT_ERROR;
            size_t pos = 0;
            pos += snprintf(expr + pos, len - pos, "(");
            int first = 1;
            for (int i = 0; i < ntypes; i++) {
                if (sel[i]) {
                    if (!first) pos += snprintf(expr + pos, len - pos, " or ");
                    pos += snprintf(expr + pos, len - pos, "%s", types[i].type);
                    first = 0;
                }
            }
            pos += snprintf(expr + pos, len - pos, ")");
            opts->packet_type = expr;
            return MENU_RESULT_CAPTURE;
            }
        }
    } while (1);
}

/* ---------------------------------------------------------------------------
 * 3) Text input prompt
 * --------------------------------------------------------------------------- */
static enum menu_result prompt_text(const char *title,
                                   const char *prompt,
                                   char *buf,
                                   size_t bufsz,
                                   int *cancelled)
{
    int rows = 7;
    int cols = COLS - 8;
    if (cols < 40) cols = 40;
    if (cols > COLS) cols = COLS;

    int top = (LINES - rows) / 2;
    int left = (COLS - cols) / 2;
    if (top < 0) top = 0;
    if (left < 0) left = 0;

    WINDOW *win = newwin(rows, cols, top, left);
    if (!win) return MENU_RESULT_ERROR;

    box(win, 0, 0);
    mvwaddstr(win, 1, 2, title);
    mvwaddstr(win, 3, 2, prompt);
    wmove(win, 4, 2);
    wclrtoeol(win);
    wrefresh(win);

    curs_set(1);
    echo();

    buf[0] = '\0';
    int rc = wgetnstr(win, buf, (int)bufsz - 1);

    noecho();
    curs_set(0);

    if (rc == ERR) {
        delwin(win);
        return MENU_RESULT_CANCEL;
    }

    if (buf[0] == 27 || (buf[0] == 'q' && buf[1] == '\0')) {
        if (cancelled) *cancelled = 1;
        buf[0] = '\0';
        delwin(win);
        return MENU_RESULT_CAPTURE;
    }

    delwin(win);
    return MENU_RESULT_CAPTURE;
}

/* ---------------------------------------------------------------------------
 * 4) Confirmation screen
 * --------------------------------------------------------------------------- */
static enum menu_result confirm_capture(const char *dev_name,
                                       const struct sniffer_options *opts)
{
    int rows = 12;
    int cols = COLS - 8;
    if (cols < 60) cols = 60;
    if (cols > COLS) cols = COLS;

    int top = (LINES - rows) / 2;
    int left = (COLS - cols) / 2;
    if (top < 0) top = 0;
    if (left < 0) left = 0;

    WINDOW *win = newwin(rows, cols, top, left);
    if (!win) return MENU_RESULT_ERROR;

    box(win, 0, 0);
    mvwaddstr(win, 1, 2, " Capture Setup - Confirm ");
    mvwprintw(win, 3, 2, "Interface : %s", dev_name);
    mvwprintw(win, 4, 2, "Packet type: %s",
              opts->packet_type && strcmp(opts->packet_type, "all") ? opts->packet_type : "(all)");
   mvwprintw(win, 5, 2, "IPv4 filter: %s", opts->ip_addr ? opts->ip_addr : "(none)");
    if (opts->port)
        mvwprintw(win, 6, 2, "Port filter : %u", opts->port);
    else
        mvwprintw(win, 6, 2, "Port filter : (none)");

   mvwaddstr(win, 8, 2, "Enter: start capture    q / Esc: cancel");
    wrefresh(win);

    int ch = wgetch(win);
    delwin(win);

    if (ch == '\n' || ch == KEY_ENTER || ch == 13 || ch == 10)
        return MENU_RESULT_CAPTURE;
    return MENU_RESULT_CANCEL;
}

/* ---------------------------------------------------------------------------
 * Main TUI entry point
 * --------------------------------------------------------------------------- */
enum menu_result menu_capture_setup(pcap_if_t *alldevs,
                                   const char **dev_out,
                                   struct sniffer_options *opts_out,
                                   char *errbuf,
                                   size_t errbuf_size)
{
    (void)errbuf;
    (void)errbuf_size;

    if (!alldevs || !dev_out || !opts_out)
        return MENU_RESULT_ERROR;

    *dev_out = NULL;
    memset(opts_out, 0, sizeof(*opts_out));

    if (tui_init() != 0)
        return MENU_RESULT_ERROR;

    enum menu_result rc;

    /* Step 1: Interface */
    rc = select_interface(alldevs, dev_out);
    if (rc != MENU_RESULT_CAPTURE)
        goto done;

    /* Step 2: Packet types */
    rc = select_packet_types(opts_out);
    if (rc != MENU_RESULT_CAPTURE)
        goto done;

    /* Step 3: IPv4 (optional) */
    {
        char ip[INET_ADDRSTRLEN + 1] = {0};
        int cancelled = 0;
        for (int retry = 0; retry < 3; retry++) {
            erase();
            rc = prompt_text("Filter by IPv4 address",
                             "Address (enter empty to skip):",
                             ip, sizeof(ip), &cancelled);
            if (rc == MENU_RESULT_ERROR) goto done;
            if (cancelled) { rc = MENU_RESULT_CANCEL; goto done; }
            if (ip[0] == '\0') break;
            struct in_addr a;
            if (inet_pton(AF_INET, ip, &a) == 1) {
                opts_out->ip_addr = strdup(ip);
                if (!opts_out->ip_addr) { rc = MENU_RESULT_ERROR; goto done; }
                break;
            }
            draw_status("Invalid IPv4 address. Press any key to retry...");
            getch();
            ip[0] = '\0';
        }
    }

    /* Step 4: Port (optional) */
    {
        char portbuf[16] = {0};
        int cancelled = 0;
        for (int retry = 0; retry < 3; retry++) {
            erase();
            rc = prompt_text("Filter by TCP/UDP port",
                             "Port (1-65535, empty to skip):",
                             portbuf, sizeof(portbuf), &cancelled);
            if (rc == MENU_RESULT_ERROR) goto done;
            if (cancelled) { rc = MENU_RESULT_CANCEL; goto done; }
            if (portbuf[0] == '\0') break;
            char *end = NULL;
            unsigned long v = strtoul(portbuf, &end, 10);
            if (*end == '\0' && v >= 1 && v <= 65535) {
                opts_out->port = (unsigned short)v;
                break;
            }
            draw_status("Invalid port (1-65535). Press any key to retry...");
            getch();
            portbuf[0] = '\0';
        }
    }

    /* Step 5: Confirm */
    erase();
    rc = confirm_capture(*dev_out, opts_out);

done:
    tui_done();
    return rc;
}

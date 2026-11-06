/*
 * netwatch - Μικρό εργαλείο παρακολούθησης οικιακού δικτύου (Linux, Layer 2)
 *
 * Λειτουργίες:
 *   - Εντοπισμός άγνωστων συσκευών (whitelist γνωστών MAC)
 *   - Στατιστικά ανά συσκευή (πακέτα, bytes, first/last seen)
 *   - Αναγνώριση κατασκευαστή (μικρός OUI πίνακας + ανίχνευση τυχαίων MAC)
 *   - Ανίχνευση ARP spoofing (πίνακας IP -> MAC)
 *   - Log με timestamps, SIGHUP = reload λίστας, SIGUSR1 = dump, SIGINT = έξοδος
 *
 * Χρήση μόνο σε δίκτυα που σου ανήκουν ή έχεις άδεια να παρακολουθείς.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define HASH_SIZE 256 /* δύναμη του 2 */

/* ---------- Δομές δεδομένων ---------- */

typedef struct Device {
    uint8_t mac[6];
    uint8_t known;      /* είναι στη whitelist; */
    uint8_t seen;       /* έχει εμφανιστεί σε αυτή τη συνεδρία; */
    uint32_t ip;        /* τελευταία IP (από ARP), network order */
    time_t first_seen, last_seen;
    uint64_t packets, bytes;
    char name[32];
    struct Device *next;
} Device;

typedef struct ArpEntry {
    uint32_t ip;
    uint8_t mac[6];
    struct ArpEntry *next;
} ArpEntry;

static Device *dev_table[HASH_SIZE];
static ArpEntry *arp_table[HASH_SIZE];

static volatile sig_atomic_t running = 1, do_reload = 0, do_dump = 0;
static FILE *logfile = NULL;
static const char *known_path = NULL;
static int learn_mode = 0;
static uint8_t own_mac[6];

/* ---------- Βοηθητικά ---------- */
/* Καταγράφει ένα μήνυμα στην οθόνη (printf) και προαιρετικά στο αρχείο logfile */
static void log_event(const char *level, const char *fmt, ...) {
    char ts[32], msg[512];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    printf("%s [%-5s] %s\n", ts, level, msg);
    fflush(stdout);
    if (logfile) {
        fprintf(logfile, "%s [%-5s] %s\n", ts, level, msg);
        fflush(logfile);
    }
}
/* Μετατρέπει τα 6 bytes μιας MAC address σε όμορφο κείμενο (π.χ. aa:bb:cc...) */
static void mac_str(const uint8_t *m, char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}
/* Παίρνει μια MAC σε κείμενο (π.χ. από το known.txt) και την κάνει 6 καθαρά bytes */
static int parse_mac(const char *s, uint8_t *m) {
    unsigned v[6];
    if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) m[i] = (uint8_t)v[i];
    return 0;
}
/* Παίρνει μια IP αριθμό και τη μετατρέπει σε κλασική μορφή κειμένου (π.χ. 192.168.1.1) */
static void ip_str(uint32_t ip, char out[INET_ADDRSTRLEN]) {
    inet_ntop(AF_INET, &ip, out, INET_ADDRSTRLEN);
}


/* ελεγχει τα πρωτα 3 bytes της mac και βλεπει αν ξερει τον κατασκευαστη */
static const struct { uint8_t oui[3]; const char *name; } oui_db[] = {
    {{0x00, 0x0c, 0x29}, "VMware"},
    {{0x00, 0x50, 0x56}, "VMware"},
    {{0x08, 0x00, 0x27}, "VirtualBox"},
    {{0x52, 0x54, 0x00}, "QEMU/KVM"},
    {{0xb8, 0x27, 0xeb}, "Raspberry Pi"},
    {{0xdc, 0xa6, 0x32}, "Raspberry Pi"},
    {{0x00, 0x50, 0xf2}, "Microsoft (Surface/Xbox)"},
    {{0x00, 0x1b, 0x21}, "Intel (Network Card)"},
    {{0x00, 0x06, 0x5b}, "Dell PC"},
    {{0x00, 0x14, 0x38}, "Hewlett-Packard (HP)"},
    {{0xf8, 0xfe, 0x5e}, "Intel"},
};
/* Κοιτάζει τη MAC, ελέγχει αν είναι τυχαία (κινητό) ή ψάχνει στον πίνακα για κατασκευαστή */
static const char *vendor_of(const uint8_t *mac) {
    /* Αν το bit είναι αναμμένο, είναι τυχαία MAC για προστασία ιδιωτικότητας (π.χ. κινητό) */
    if (mac[0] & 0x02) return "Τυχαία/τοπική MAC (πιθανώς κινητό)";
    for (size_t i = 0; i < sizeof oui_db / sizeof oui_db[0]; i++)
        if (memcmp(oui_db[i].oui, mac, 3) == 0) return oui_db[i].name;
    return "Άγνωστος";
}

/* ---------- Hash tables ---------- */
/* Μαθηματικός αλγόριθμος FNV-1a: Παίρνει τη MAC και βγάζει αριθμό θέσης (0-255) */
static unsigned hash_mac(const uint8_t *mac) { /* FNV-1a */
    unsigned h = 2166136261u;
    for (int i = 0; i < 6; i++) { h ^= mac[i]; h *= 16777619u; }
    return h & (HASH_SIZE - 1);
}
/* Παίρνει την IP και βγάζει αριθμό θέσης για το arp_table (0-255) */
static unsigned hash_ip(uint32_t ip) {
    return (ip * 2654435761u) >> 24; /* 8 πάνω bits -> 0..255 */
}
/* αν υπαρχει ηδη ή οχι φαινετε απο το created  αλλιως το δημιουργει εκει*/
/* επιστρεφει δεικτη στο ιδιο το device */
static Device *find_or_add(const uint8_t *mac, int *created) {

    /* βρισκει την θεση του στο hashmap με τις mac adresses*/
    unsigned idx = hash_mac(mac);

    /* πηγαινει μεσα στο συρταρι idx και ψαχνει μεσα στην λιστα αυτου αν το βρει
     * επιστεφει το device και βαζειτο created=0 για να δειξει οτι υπηρχε */
    for (Device *d = dev_table[idx]; d; d = d->next)
        if (memcmp(d->mac, mac, 6) == 0) {
            if (created) *created = 0;
            return d;
        }

    /* δεσμευει μνημη για την νεα συσκευη */
    Device *d = calloc(1, sizeof *d);
    if (!d) { perror("calloc"); exit(1); }

    /* αρχικοποιει τα πεδια των devices επειδη τωρα δημιουργηθηκε created-1*/
    memcpy(d->mac, mac, 6);
    d->next = dev_table[idx];
    dev_table[idx] = d;
    if (created) *created = 1;
    return d;
}
/* Σημειώνει μια συσκευή ως γνωστή/έμπιστη και της βάζει όνομα (π.χ. από το known.txt) */
static void add_known(const uint8_t *mac, const char *name) {
    Device *d = find_or_add(mac, NULL);
    d->known = 1;
    if (name && *name) snprintf(d->name, sizeof d->name, "%s", name);
}

/* ---------- Αρχείο γνωστών συσκευών ---------- */
/* Μορφή γραμμής:  aa:bb:cc:dd:ee:ff  προαιρετικό όνομα */

/* ΦΟΡΤΩΣΗ: Διαβάζει το αρχείο known.txt όταν ξεκινάει το πρόγραμμα */
static int load_known(const char *path) {

    /* Ανοίγουμε το αρχείο (π.χ. known.txt) για ανάγνωση ("r" = read) */
    FILE *f = fopen(path, "r");

    if (!f) {
        /* Αν το αρχείο δεν υπάρχει ή δεν ανοίγει, καταγράφουμε προειδοποίηση και φεύγουμε */
        log_event("WARN", "Δεν ανοίγει το %s: %s", path, strerror(errno));
        return -1;
    }
    char line[256];
    int n = 0;
    /* για καθε γραμμη */
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        /* αγνοει τα κενα που μπορει να εχει πριν*/
        while (isspace((unsigned char)*p)) p++;

        /* αν αρχιζει με σχολιο η ειναι null πηγαινε στην επομενη γραμμη*/
        if (!*p || *p == '#') continue;

        /* αν δεν βγαινει σωστο mac adress σε string βγαλε warning και αλλαξε γραμμη*/
        uint8_t mac[6];
        if (parse_mac(p, mac) < 0) {
            log_event("WARN", "Μη έγκυρη γραμμή στο %s: %s", path, p);
            continue;
        }

        /* βλεπει αν εχει σχολια (μεγεθος mac 17 char) και βαζει αυτο στο name*/
        char *name = (strlen(p) > 17) ? p + 17 : "";
        while (isspace((unsigned char)*name)) name++;
        name[strcspn(name, "\r\n")] = '\0';

        /* την κανει εμπιστη και αποθηκευει και το ονομα*/
        add_known(mac, name);

        /*μετρητης συσκευων*/
        n++;
    }
    fclose(f);

    /* οταν τελειωσει εκτυπωνει ποσες συσκευες βρεθηκαν */
    log_event("INFO", "Φορτώθηκαν %d γνωστές συσκευές από %s", n, path);
    return n;
}

static void save_known(const char *path) {

    /* ανοιγει τον φακελο για να γραψει*/
    FILE *f = fopen(path, "w");

    /*αν δεν ανοιξε το δειχνει*/
    if (!f) {
        log_event("WARN", "Αδυναμία εγγραφής στο %s: %s", path, strerror(errno));
        return;
    }

    /* περναει μια μια τις συσκευεσ και ελεγχει αν ειναι εμπιστες known=1 και τις τυπωνει*/
    fprintf(f, "# netwatch - γνωστές συσκευές (MAC  όνομα)\n");
    int n = 0;
    for (int i = 0; i < HASH_SIZE; i++)
        for (Device *d = dev_table[i]; d; d = d->next)
            if (d->known) {
                char m[18];
                mac_str(d->mac, m);
                fprintf(f, "%s %s\n", m, d->name);
                n++;
            }
    fclose(f);
    log_event("INFO", "Αποθηκεύτηκαν %d συσκευές στο %s", n, path);
}

/* ---------- Αναφορά ---------- */

static void print_devices(void) {
    /* οταν τελειωνει τυπωνει ολα τα αποτελεσματα στην οθονη*/
    printf("\n%-18s %-15s %-8s %9s %10s  %-19s %s\n",
           "MAC", "IP", "Status", "Packets", "Bytes", "Last seen", "Vendor / Όνομα");

    for (int i = 0; i < HASH_SIZE; i++)
        for (Device *d = dev_table[i]; d; d = d->next) {
            if (!d->seen) continue;
            char m[18], ip[INET_ADDRSTRLEN] = "-", ts[32];
            mac_str(d->mac, m);
            if (d->ip) ip_str(d->ip, ip);
            struct tm tmv;
            localtime_r(&d->last_seen, &tmv);
            strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);
            printf("%-18s %-15s %-8s %9llu %10llu  %-19s %s %s\n", m, ip,
                   d->known ? "known" : "UNKNOWN",
                   (unsigned long long)d->packets, (unsigned long long)d->bytes,
                   ts, vendor_of(d->mac), d->name);
        }
    printf("\n");
}

/* ---------- Ανίχνευση ARP spoofing ---------- */

static void handle_arp(const uint8_t *frame, ssize_t len, Device *src) {
    /* το μεγεθος του ethernet frame και μετα ακολουθει το arp header και arp payload που ειναι 28 byte συνολο*/
    const ssize_t need = sizeof(struct ethhdr) + 8 + 20;

    /* αν ειναι λιγοτερο ειναι κατεστραμενο πακετο*/
    if (len < need) return;

    /* παμε το πακετο 14 byte δεξια να κοιταμε κατευθειαν το arp header και το αποθηκευουμε σε δεικτη προς arp header*/
    const uint8_t *arp = frame + sizeof(struct ethhdr);
    const struct arphdr *ah = (const struct arphdr *)arp;

    /* ελεγχει οτι ειναι arp header οτι ειναι ipv4 και οτι εχει μεγεθος mac 6 και ip 4 bytes*/
    if (ah->ar_hrd != htons(ARPHRD_ETHER) || ah->ar_pro != htons(ETH_P_IP) ||
        ah->ar_hln != 6 || ah->ar_pln != 4)
        return;

     /* προσπερναει το header arp για να παει στο payload της*/
    /*ξεχωριζει το πεδιο sender hardware (mac) adress και sender protocol (ip) adress*/
    const uint8_t *sha = arp + 8;
    uint32_t spa;
    memcpy(&spa, arp + 14, 4);
    if (spa == 0) return; /* ARP probe (0.0.0.0) - αγνοει */

    char shas[18], srcs[18], ips[INET_ADDRSTRLEN];
    mac_str(sha, shas);
    mac_str(src->mac, srcs);
    ip_str(spa, ips);

    /* Έλεγχος 1: το MAC μέσα στο ARP πρέπει να ταιριάζει με το Ethernet source */
    if (memcmp(sha, src->mac, 6) != 0)
        log_event("ALERT", "ARP ασυνέπεια: Ethernet src=%s αλλά ARP sender=%s (IP %s)",
                  srcs, shas, ips);

    src->ip = spa;

    /* Έλεγχος 2: η ίδια IP άλλαξε MAC; */
    unsigned idx = hash_ip(spa);
    for (ArpEntry *e = arp_table[idx]; e; e = e->next) {
        if (e->ip != spa) continue;
        if (memcmp(e->mac, sha, 6) != 0) {
            char olds[18];
            mac_str(e->mac, olds);
            log_event("ALERT", "ΠΙΘΑΝΟ ARP SPOOFING: η IP %s άλλαξε MAC %s -> %s",
                      ips, olds, shas);
            memcpy(e->mac, sha, 6);
        }
        return;
    }
    ArpEntry *e = calloc(1, sizeof *e);
    if (!e) { perror("calloc"); exit(1); }
    e->ip = spa;
    memcpy(e->mac, sha, 6);
    e->next = arp_table[idx];
    arp_table[idx] = e;
    log_event("INFO", "Νέα αντιστοίχιση ARP: %s -> %s", ips, shas);
}

/* ---------- Επεξεργασία frame ---------- */

static void handle_frame(const uint8_t *frame, ssize_t len) {
    const struct ethhdr *eth = (const struct ethhdr *)frame;
    int created;
    Device *d = find_or_add(eth->h_source, &created);
    time_t now = time(NULL);

    d->packets++;
    d->bytes += (uint64_t)len;
    d->last_seen = now;

    if (!d->seen) {
        d->seen = 1;
        d->first_seen = now;
        char m[18];
        mac_str(d->mac, m);
        if (d->known) {
            log_event("INFO", "Γνωστή συσκευή online: %s %s", m, d->name);
        } else if (learn_mode) {
            d->known = 1;
            log_event("LEARN", "Νέα συσκευή καταχωρήθηκε: %s [%s]", m, vendor_of(d->mac));
        } else {
            log_event("ALERT", "ΑΓΝΩΣΤΗ ΣΥΣΚΕΥΗ: %s [%s]", m, vendor_of(d->mac));
        }
    }

    if (ntohs(eth->h_proto) == ETH_P_ARP)
        handle_arp(frame, len, d);
}

/* ---------- Signals ---------- */

static void on_sigint(int s) { (void)s; running = 0; }
static void on_sighup(int s) { (void)s; do_reload = 1; }
static void on_sigusr1(int s) { (void)s; do_dump = 1; }

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* χωρίς SA_RESTART: το recvfrom διακόπτεται με EINTR */

    sa.sa_handler = on_sigint;  sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = on_sighup;  sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = on_sigusr1; sigaction(SIGUSR1, &sa, NULL);
}

/* ---------- Καθαρισμός ---------- */

static void free_all(void) {
    for (int i = 0; i < HASH_SIZE; i++) {
        for (Device *d = dev_table[i]; d;) { Device *n = d->next; free(d); d = n; }
        for (ArpEntry *e = arp_table[i]; e;) { ArpEntry *n = e->next; free(e); e = n; }
        dev_table[i] = NULL;
        arp_table[i] = NULL;
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Χρήση: sudo %s -i <interface> [-k known.txt] [-l netwatch.log] [-L]\n"
        "  -i  διεπαφή δικτύου (π.χ. eth0, wlan0)\n"
        "  -k  αρχείο γνωστών συσκευών (whitelist)\n"
        "  -l  αρχείο log\n"
        "  -L  learn mode: οι νέες συσκευές θεωρούνται γνωστές και\n"
        "      αποθηκεύονται στο -k αρχείο κατά την έξοδο\n"
        "Signals: SIGHUP=reload whitelist, SIGUSR1=πίνακας συσκευών, Ctrl+C=έξοδος\n",
        prog);
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    const char *iface = NULL, *log_path = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "i:k:l:Lh")) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'k': known_path = optarg; break;
        case 'l': log_path = optarg; break;
        case 'L': learn_mode = 1; break;
        default: usage(argv[0]); return 1;
        }
    }
    if (!iface) { usage(argv[0]); return 1; }
    if (learn_mode && !known_path) {
        fprintf(stderr, "Το -L χρειάζεται και -k <αρχείο>.\n");
        return 1;
    }

    if (log_path) {
        logfile = fopen(log_path, "a");
        if (!logfile) perror("fopen log");
    }

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket (χρειάζεται root)");
        return 1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sock);
        return 1;
    }
    int ifindex = ifr.ifr_ifindex;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(sock);
        return 1;
    }
    memcpy(own_mac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(sock, (struct sockaddr *)&sll, sizeof sll) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    install_signals();

    add_known(own_mac, "this-host");
    if (known_path) load_known(known_path);

    char ms[18];
    mac_str(own_mac, ms);
    log_event("INFO", "netwatch ξεκίνησε στο %s (MAC %s)%s", iface, ms,
              learn_mode ? " [LEARN MODE]" : "");

    uint8_t buf[2048];
    while (running) {
        if (do_reload) {
            do_reload = 0;
            for (int i = 0; i < HASH_SIZE; i++)
                for (Device *d = dev_table[i]; d; d = d->next) d->known = 0;
            add_known(own_mac, "this-host");
            if (known_path) load_known(known_path);
        }
        if (do_dump) {
            do_dump = 0;
            print_devices();
        }

        struct sockaddr_ll from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(sock, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }
        if (n < (ssize_t)sizeof(struct ethhdr)) continue;
        if (from.sll_pkttype == PACKET_OUTGOING) continue; /* δικά μας πακέτα */

        handle_frame(buf, n);
    }

    log_event("INFO", "Τερματισμός...");
    print_devices();
    if (learn_mode && known_path) save_known(known_path);

    close(sock);
    free_all();
    if (logfile) fclose(logfile);
    return 0;
}
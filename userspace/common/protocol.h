#ifndef KGUARD_PROTOCOL_H
#define KGUARD_PROTOCOL_H

#include <stdint.h>

#define KGUARD_NETLINK_FAMILY 31
#define KGUARD_MAX_PAYLOAD 256

enum kguard_msg_type {
    KGUARD_MSG_HELLO = 1,
    KGUARD_MSG_STATUS_REQ = 2,
    KGUARD_MSG_STATUS_RESP = 3,
    KGUARD_MSG_BLOCK_IP = 4,
    KGUARD_MSG_UNBLOCK_IP = 5,
    KGUARD_MSG_EVENT = 6,
    KGUARD_MSG_LIST_REQ = 7,
    KGUARD_MSG_LIST_RESP = 8
};

struct kguard_msg {
    uint16_t type;
    uint16_t reserved;
    uint32_t pid;
    char payload[KGUARD_MAX_PAYLOAD];
};

#endif


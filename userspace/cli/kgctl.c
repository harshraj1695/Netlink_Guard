#include "../common/protocol.h"

#include <errno.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RECV_TIMEOUT_MS 1000

static int open_netlink(void)
{
    int fd;
    struct sockaddr_nl local = {0};

    fd = socket(AF_NETLINK, SOCK_RAW, KGUARD_NETLINK_FAMILY);
    if (fd < 0)
        return -1;

    local.nl_family = AF_NETLINK;
    local.nl_pid = getpid();
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

static int send_netlink_request(int fd, uint16_t type, const char *payload)
{
    struct sockaddr_nl peer = {
        .nl_family = AF_NETLINK,
    };
    struct {
        struct nlmsghdr nlh;
        struct kguard_msg msg;
    } request = {0};

    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(request.msg));
    request.nlh.nlmsg_pid = getpid();
    request.msg.type = type;
    request.msg.pid = getpid();
    if (payload)
        strncpy(request.msg.payload, payload, sizeof(request.msg.payload) - 1);

    return sendto(fd, &request, request.nlh.nlmsg_len, 0,
                  (struct sockaddr *)&peer, sizeof(peer));
}

static int recv_netlink_response(int fd, struct kguard_msg *out, int timeout_ms)
{
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };
    struct {
        struct nlmsghdr nlh;
        struct kguard_msg msg;
    } reply = {0};

    if (poll(&pfd, 1, timeout_ms) <= 0)
        return -1;

    ssize_t n = recv(fd, &reply, sizeof(reply), 0);
    if (n < 0)
        return -1;

    *out = reply.msg;
    return 0;
}

static int request_and_print(uint16_t type, const char *payload, uint16_t expected)
{
    int fd = open_netlink();
    if (fd < 0) {
        perror("netlink socket");
        return 1;
    }

    if (send_netlink_request(fd, type, payload) < 0) {
        perror("send");
        close(fd);
        return 1;
    }

    struct kguard_msg resp = {0};
    if (recv_netlink_response(fd, &resp, RECV_TIMEOUT_MS) < 0) {
        fprintf(stderr, "timeout waiting for reply\n");
        close(fd);
        return 1;
    }
    close(fd);

    if (expected && resp.type != expected) {
        fprintf(stderr, "unexpected response (%u)\n", resp.type);
        return 1;
    }

    printf("%s\n", resp.payload);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s <command>\n", prog);
    fprintf(stderr, "  %s status\n", prog);
    fprintf(stderr, "  %s list\n", prog);
    fprintf(stderr, "  %s block <ip>\n", prog);
    fprintf(stderr, "  %s unblock <ip>\n", prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "status"))
        return request_and_print(KGUARD_MSG_STATUS_REQ, NULL, KGUARD_MSG_STATUS_RESP);

    if (!strcmp(argv[1], "list"))
        return request_and_print(KGUARD_MSG_LIST_REQ, NULL, KGUARD_MSG_LIST_RESP);

    if (!strcmp(argv[1], "block")) {
        if (argc != 3) {
            usage(argv[0]);
            return 1;
        }
        return request_and_print(KGUARD_MSG_BLOCK_IP, argv[2], KGUARD_MSG_EVENT);
    }

    if (!strcmp(argv[1], "unblock")) {
        if (argc != 3) {
            usage(argv[0]);
            return 1;
        }
        return request_and_print(KGUARD_MSG_UNBLOCK_IP, argv[2], KGUARD_MSG_EVENT);
    }

    usage(argv[0]);
    return 1;
}

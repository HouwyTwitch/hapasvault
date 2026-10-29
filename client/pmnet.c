#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
typedef int socklen_t;
#  define CLOSESOCK closesocket
#  define OSSOCK(s) ((SOCKET)(s))
#else
#  define _POSIX_C_SOURCE 200809L
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  define CLOSESOCK close
#  define OSSOCK(s) ((int)(s))
#endif

#include "pmnet.h"
#include <string.h>

int pm_net_init(void)
{
#ifdef _WIN32
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0 ? 0 : -1;
#else
    return 0;
#endif
}

static void nodelay(pm_sock s)
{
    int one = 1;
    setsockopt(OSSOCK(s), IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
}

pm_sock pm_net_listen(uint16_t port)
{
    pm_sock s = (pm_sock)socket(AF_INET, SOCK_STREAM, 0);
    if (s == PM_BAD_SOCK) return PM_BAD_SOCK;
    int one = 1;
    setsockopt(OSSOCK(s), SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);     /* наружу не слушаем */
    if (bind(OSSOCK(s), (struct sockaddr *)&a, sizeof a) != 0 || listen(OSSOCK(s), 1) != 0) {
        CLOSESOCK(OSSOCK(s));
        return PM_BAD_SOCK;
    }
    return s;
}

pm_sock pm_net_accept(pm_sock ls)
{
    pm_sock s = (pm_sock)accept((int)ls, NULL, NULL);
    if (s != PM_BAD_SOCK) nodelay(s);
    return s;
}

pm_sock pm_net_connect(const char *host, uint16_t port)
{
    pm_sock s = (pm_sock)socket(AF_INET, SOCK_STREAM, 0);
    if (s == PM_BAD_SOCK) return PM_BAD_SOCK;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1 ||
        connect(OSSOCK(s), (struct sockaddr *)&a, sizeof a) != 0) {
        CLOSESOCK(OSSOCK(s));
        return PM_BAD_SOCK;
    }
    nodelay(s);
    return s;
}

int pm_net_wait(pm_sock s, int timeout_ms)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(OSSOCK(s), &fds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select((int)(s + 1), &fds, NULL, NULL, &tv);
    return r < 0 ? -1 : r > 0;
}

static int send_all(pm_sock s, const uint8_t *p, size_t n)
{
    while (n) {
        int k = (int)send(OSSOCK(s), (const char *)p, (int)n, 0);
        if (k <= 0) return -1;
        p += k; n -= (size_t)k;
    }
    return 0;
}

static int recv_all(pm_sock s, uint8_t *p, size_t n)
{
    while (n) {
        int k = (int)recv(OSSOCK(s), (char *)p, (int)n, 0);
        if (k <= 0) return -1;
        p += k; n -= (size_t)k;
    }
    return 0;
}

int pm_net_send_frame(pm_sock s, const uint8_t *buf, size_t len)
{
    uint8_t h[4] = {(uint8_t)len, (uint8_t)(len >> 8), (uint8_t)(len >> 16), (uint8_t)(len >> 24)};
    if (send_all(s, h, 4) != 0) return -1;
    return send_all(s, buf, len);
}

long pm_net_recv_frame(pm_sock s, uint8_t *buf, size_t cap)
{
    uint8_t h[4];
    if (recv_all(s, h, 4) != 0) return -1;
    size_t len = (size_t)h[0] | (size_t)h[1] << 8 | (size_t)h[2] << 16 | (size_t)h[3] << 24;
    if (len > cap) return -1;
    if (recv_all(s, buf, len) != 0) return -1;
    return (long)len;
}

void pm_net_close(pm_sock s)
{
    if (s != PM_BAD_SOCK) CLOSESOCK(OSSOCK(s));
}

long pm_net_xfer(void *ctx, const uint8_t *req, size_t req_len, uint8_t *resp, size_t cap)
{
    pm_sock s = *(pm_sock *)ctx;
    if (pm_net_send_frame(s, req, req_len) != 0) return -1;
    return pm_net_recv_frame(s, resp, cap);
}

#include "unet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static void unetSetError(char *err, const char *fmt, ...) {
  va_list ap;

  if (!err)
    return;
  va_start(ap, fmt);
  vsnprintf(err, UNET_ERR_LEN, fmt, ap);
  va_end(ap);
}

int unetSetBlock(char *err, int fd, int non_block) {
  int flags;

  if ((flags = fcntl(fd, F_GETFL)) == -1) {
    unetSetError(err, "fcntl(F_GETFL): %s", strerror(errno));
    return UNET_ERR;
  }

  if (non_block)
    flags |= O_NONBLOCK;
  else
    flags &= ~O_NONBLOCK;

  if (fcntl(fd, F_SETFL, flags) == -1) {
    unetSetError(err, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
    return UNET_ERR;
  }
  return UNET_OK;
}

int unetSetSendBuffer(char *err, int fd, int buffsize) {
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffsize, sizeof(buffsize)) ==
      -1) {
    unetSetError(err, "setsockopt SO_SNDBUF: %s", strerror(errno));
    return UNET_ERR;
  }
  return UNET_OK;
}

int unetMaximizeSendBuffer(char *err, int fd) {
  socklen_t intsize = sizeof(int);
  int min, max, avg;
  int old_size;

  if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &old_size, &intsize) != 0) {
    close(fd);
    unetSetError(err, "getsockopt(SO_SNDBUF)");
    return UNET_ERR;
  }

  min = old_size;
  max = 256 * 1024 * 1024;

  while (min <= max) {
    avg = ((unsigned int)(min + max)) / 2;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&avg, intsize) == 0) {
      min = avg + 1;
    } else {
      max = avg - 1;
    }
  }
  return 0;
}

static int unetSetReuseAddr(char *err, int fd) {
  int yes = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
    unetSetError(err, "setsockopt SO_REUSEADDR: %s", strerror(errno));
    return UNET_ERR;
  }
  return UNET_OK;
}

int unetSetMulticastTTL(char *err, int fd, int ttl) {
  if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
    unetSetError(err, "setsockopt IP_MULTICAST_TTL: %s", strerror(errno));
    return UNET_ERR;
  }
  return UNET_OK;
}

int unetSetMulticastGroup(char *err, char *addr, int fd) {
  struct ip_mreq mreq;
  memset(&mreq, 0, sizeof(struct ip_mreq));
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  mreq.imr_multiaddr.s_addr = inet_addr(addr);
  if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) ==
      -1) {
    unetSetError(err, "setsockopt IP_ADD_MEMBERSHIP: %s", strerror(errno));
    return UNET_ERR;
  }
  return UNET_OK;
}

int unetCreateSocket(char *err, const int domain, const int type) {
  int s;
  if ((s = socket(domain, type, 0)) == -1) {
    unetSetError(err, "creating socket: %s", strerror(errno));
    return UNET_ERR;
  }

  if (unetSetReuseAddr(err, s) == UNET_ERR) {
    close(s);
    return UNET_ERR;
  }
  return s;
}

int unetUdpServer(char *err, char *bindaddr, int port) {
  int sockfd;
  struct sockaddr_in sa;

  sockfd = unetCreateSocket(err, AF_INET, SOCK_DGRAM);
  if (!sockfd) {
    return UNET_ERR;
  }

  if (unetSetBlock(err, sockfd, 1) == UNET_ERR) {
    close(sockfd);
    return UNET_ERR;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_ANY);
  sa.sin_port = htons(port);
  if (bindaddr && inet_aton(bindaddr, &sa.sin_addr) == 0) {
    unetSetError(err, "invalid bind address");
    close(sockfd);
    return UNET_ERR;
  }

  if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
    unetSetError(err, "bind: %s", strerror(errno));
    close(sockfd);
    return UNET_ERR;
  }
  return sockfd;
}

int unetUdpSocket(char *err) {
  int sockfd;
  sockfd = unetCreateSocket(err, AF_INET, SOCK_DGRAM);
  if (!sockfd) {
    return UNET_ERR;
  }
  return sockfd;
}

int unetUdpSendTo(char *err, int fd, char *addr, int port, void *buf, int len) {
  int nwritten = 0;
  struct sockaddr_in sa;

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr(addr);
  sa.sin_port = htons(port);

  nwritten = sendto(fd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
  if (nwritten == -1) {
    unetSetError(err, "sendto: %s", strerror(errno));
    return UNET_ERR;
  }
  return nwritten;
}

int unetUdpRecvFrom(char *err, int fd, char *ip, size_t ip_len, int *port,
                    void *buf, int len) {
  int nread = 0;
  struct sockaddr_storage sa;
  socklen_t sa_len = sizeof(sa);
  nread = recvfrom(fd, buf, len, 0, (struct sockaddr *)&sa, &sa_len);
  if (nread == -1) {
    unetSetError(err, "recvfrom: %s", strerror(errno));
    return UNET_ERR;
  }
  if (sa.ss_family == AF_INET) {
    struct sockaddr_in *s = (struct sockaddr_in *)&sa;
    if (ip)
      inet_ntop(AF_INET, (void *)&(s->sin_addr), ip, ip_len);
    if (port)
      *port = ntohs(s->sin_port);
  } else {
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&sa;
    if (ip)
      inet_ntop(AF_INET6, (void *)&(s->sin6_addr), ip, ip_len);
    if (port)
      *port = ntohs(s->sin6_port);
  }
  return nread;
}

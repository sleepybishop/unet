/* unet.c -- Basic UDP socket stuff made a bit less boring
 *
 * Based on anet.[c,h] from redis by:
 *
 * Copyright (c) 2006-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef UNET_H
#define UNET_H

#include <sys/types.h>

#define UNET_OK 0
#define UNET_ERR -1
#define UNET_ERR_LEN 256

#define UNET_NONE 0
#define UNET_IP_ONLY (1 << 0)

int unetSetBlock(char *err, int fd, int non_block);
int unetSetSendBuffer(char *err, int fd, int buffsize);
int unetMaximizeSendBuffer(char *err, int fd);
int unetSetMulticastTTL(char *err, int fd, int ttl);
int unetSetMulticastGroup(char *err, char *addr, int fd);

int unetUdpSocket(char *err);
int unetUdpServer(char *err, char *bindaddr, int port);
int unetUdpSendTo(char *err, int fd, char *addr, int port, void *buf, int len);
int unetUdpRecvFrom(char *err, int fd, char *ip, size_t ip_len, int *port,
                    void *buf, int len);

#endif

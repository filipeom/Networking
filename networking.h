#ifndef NETWORKING_H
#define NETWORKING_H
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

void dump(const unsigned char *, const unsigned int);

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_hdr {
  u_int8_t h_dest[ETHER_ADDR_LEN];
  u_int8_t h_source[ETHER_ADDR_LEN];
  u_int16_t ether_type;
};

struct ip_hdr {
  u_int8_t ip_version_and_header_length;
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t checksum;
  u_int32_t saddr;
  u_int32_t daddr;
  /* The options start here */
};

struct tcp_hdr {
  u_int16_t sport;
  u_int16_t dport;
  u_int32_t seq;
  u_int32_t ack;
  u_int8_t reserved:4;
  u_int8_t offset:4;
  u_int8_t flags;
#define TCP_FIN   0x01
#define TCP_SYN   0x02
#define TCP_RST   0x04
#define TCP_PUSH  0x08
#define TCP_ACK   0x10
#define TCP_URG   0x20
  u_int16_t window;
  u_int16_t checksum;
  u_int16_t urgent;
};

void decode_ether(const u_int8_t *);
void decode_ip(const u_int8_t *);
int decode_tcp(const u_int8_t *);

#endif

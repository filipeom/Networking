#include "networking.h"

void
dump(const unsigned char *data_buffer, const unsigned int length) {
  unsigned char byte;
  unsigned int i, j;

  for (i = 0; i < length; i++) {
    byte = data_buffer[i];
    printf("%02x ", data_buffer[i]);
    if (((i % 16) == 15) || (i == (length - 1))) {
      for (j = 0; j < 15 - (i % 16); j++) 
        printf("   ");
      printf("| ");
      for (j = (i - (i % 16)); j <= i; j++) {
        byte = data_buffer[j];
        if ((byte > 31) && (byte < 127))
          printf("%c", byte);
        else
          printf(".");
      }
      printf("\n");
    }
  }
  return;
}

void
decode_ether(const u_int8_t *frame) {
  int i;
  const struct ether_hdr *ether_hdr;

  ether_hdr = (const struct ether_hdr *) frame;
  printf("[[  Layer 2 :: Ethernet Header  ]]\n");
  printf("[ Source: %02x", ether_hdr->h_source[0]);
  for (i = 1; i < ETHER_ADDR_LEN; i++)
    printf(":%02x", ether_hdr->h_source[i]);

  printf("\tDest: %02x", ether_hdr->h_dest[0]);
  for (i = 1; i < ETHER_ADDR_LEN; i++)
    printf(":%02x", ether_hdr->h_dest[i]);

  printf("\tType: %hu ]\n", ether_hdr->ether_type);
  return;
}

void
decode_ip(const u_int8_t *datagram) {
  const struct ip_hdr *ip_hdr;

  ip_hdr = (const struct ip_hdr *) datagram;
  printf("\t((  Layer 3 ::: IP Header  ))\n");
  printf("\t( Source: %s\t", 
      inet_ntoa(*((struct in_addr *)&ip_hdr->saddr)));
  printf("\tDest: %s )\n",
      inet_ntoa(*((struct in_addr *)&ip_hdr->daddr)));
  printf("\t( Type: %u\t", ip_hdr->protocol);
  printf("ID: %hu\tLenght: %hu  )\n", 
      ntohs(ip_hdr->id), ntohs(ip_hdr->tot_len));
  return;
}

int
decode_tcp(const u_int8_t *packet) {
  u_int32_t header_size;
  const struct tcp_hdr *tcp_hdr;

  tcp_hdr = (const struct tcp_hdr *) packet;
  header_size = 4 * tcp_hdr->offset;

  printf("\t\t{{  Layer 4 :::: TCP Header  }}\n");
  printf("\t\t{ Src Port: %hu\t", ntohs(tcp_hdr->sport));
  printf("Dest Port: %hu }\n", ntohs(tcp_hdr->dport));
  printf("\t\t{ Seq #: %u\t", ntohl(tcp_hdr->seq));
  printf("Ack #: %u }\n", ntohl(tcp_hdr->ack));
  printf("\t\t{ Header size: %u\tFlags: ", header_size);
  if (tcp_hdr->flags & TCP_FIN)
    printf("FIN ");
  if (tcp_hdr->flags & TCP_SYN)
    printf("SYN ");
  if (tcp_hdr->flags & TCP_RST)
    printf("RST ");
  if (tcp_hdr->flags & TCP_PUSH)
    printf("PUSH ");
  if (tcp_hdr->flags & TCP_ACK)
    printf("ACK ");
  if (tcp_hdr->flags & TCP_URG)
    printf("URG ");
  printf(" }\n");
  return header_size;
}

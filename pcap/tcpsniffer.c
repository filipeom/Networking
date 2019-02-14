#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../networking.h"

int total = 0;
char *device;
pcap_t *pcap_handle;

int listalldevs(pcap_if_t*);
void getdevice(pcap_if_t*, int);
void packet_handler(u_int8_t*, const struct pcap_pkthdr*, const u_int8_t*);
void terminator(int);

int
main(int argc, char **agrv) {
  pcap_if_t *alldevs;
  int options;
  char errbuf[PCAP_ERRBUF_SIZE];

  signal(SIGINT, terminator);

  printf("[-] Looking up devices...\n");
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "[!] pcap_findalldevs: %s.\n", errbuf);
    exit(EXIT_FAILURE);
  }

  options = listalldevs(alldevs);
  getdevice(alldevs, options);
  printf("[-] Using device \'%s\' to analyze packets.\n", device);
  if ((pcap_handle = pcap_open_live(device, BUFSIZ, 1, -1, errbuf)) == NULL) {
    fprintf(stderr, "[!] pcap_open_live: %s.\n", errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_loop(pcap_handle, -1, packet_handler, NULL) == -1) {
    fprintf(stderr, "[!] pcap_loop: %s", pcap_geterr(pcap_handle));
    exit(EXIT_FAILURE);
  }

  printf("[-] %d packets analyzed.\n", total);

  pcap_close(pcap_handle);
  pcap_freealldevs(alldevs);
  return 0;
}

void
terminator(int signum) {
  signal(SIGINT, SIG_IGN);
  pcap_breakloop(pcap_handle);
}

void
format_time(time_t time, char *timebuf) {
  struct tm *nowtime;

  nowtime = localtime(&time);
  strftime(timebuf, 9, "%H:%M:%S", nowtime);
  return;
}

void
packet_handler(u_int8_t *user_args, const struct pcap_pkthdr *header, 
    const u_int8_t *bytes) {
  char timebuf[9];
  u_int8_t *pkt_data;
  int tcp_header_length, total_header_size, pkt_data_len;

  total++;
  format_time(header->ts.tv_sec, timebuf);
  printf("[%d] %-8s.%06ld - Frame with %d bytes\n", total, timebuf, 
      (long int)(header->ts.tv_usec), header->len);

  decode_ether(bytes);
  decode_ip(bytes+ETHER_HDR_LEN);
  tcp_header_length = decode_tcp(bytes+ETHER_HDR_LEN+sizeof(struct ip_hdr));

  total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_length;
  pkt_data = (u_int8_t *) bytes + total_header_size;
  pkt_data_len = header->len - total_header_size;
  if (pkt_data_len > 0) {
    printf("\t\t\t%u bytes of packet data\n", pkt_data_len);
    dump(pkt_data, pkt_data_len);
  } else {
    printf("\t\t\t No Packet Data left\n");
  }

  printf("\n");
  return;
}

void
getdevice(pcap_if_t *alldevs, int options) {
  int i, input;
  pcap_if_t *dev;

  printf("[+] Enter device number: ");
  scanf("%d", &input);

  if (input < 0 || input > options) {
    fprintf(stderr, "[!] Invalid device number: \'%d\' (0-%d)\n", 
        input, options);
    exit(EXIT_FAILURE);
  }

  for (i = 0, dev = alldevs; i < input; i++, dev = dev->next);
  device = dev->name;

  return;
}

int
listalldevs(pcap_if_t *alldevs) {
  int i, flag;
  pcap_if_t *dev;
  pcap_addr_t *addr;

  printf("    %-19s | %-16s | %-16s | Description\n", "Name", "Address", "Mask");
  for (i = 0, dev = alldevs; dev; i++, dev = dev->next) {
    flag = 0;
    printf("[%d] %-19s | ", i, dev->name);
    for (addr = dev->addresses; addr; addr = addr->next)
      if (addr->addr->sa_family == AF_INET) {
        printf("%-16s | ", 
            inet_ntoa(((struct sockaddr_in*)addr->addr)->sin_addr));
        printf("%-16s | ", 
            inet_ntoa(((struct sockaddr_in*)addr->netmask)->sin_addr));
        flag++;
      }
    if (!flag) 
      printf("%-16s | %-16s | ", "No IPv4 Address", "No IPv4 Mask");

    if (dev->description != NULL)
      printf("%s", dev->description);
    else
      printf("No Description available");
    printf("\n");
  }
  return i-1;
}

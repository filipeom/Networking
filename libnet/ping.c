#include <libnet.h>
#include "../pcap/device.h"

int
main(void) {
  char *devname, errbuf[LIBNET_ERRBUF_SIZE];
  char daddr_str[16];
  libnet_t *l;
  u_int32_t daddr;
  u_int16_t id, seq;
  int bytes_written;

  while ((devname = pcap_finddevice()) == NULL)
    printf("[!] Please enter a valid device number!\n");

  if ((l = libnet_init(LIBNET_RAW4, devname, errbuf)) == NULL) {
    fprintf(stderr, "[!] libnet_init() failed: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  printf("[-] Using device: \'%s\'\n", devname);
  free(devname);
  
  libnet_seed_prand(l);
  id = (u_int16_t) libnet_get_prand(LIBNET_PR16);

  printf("[+] Enter destination IP address: ");
  scanf("%15s", daddr_str);

  if ((daddr = libnet_name2addr4(l, daddr_str, 
          LIBNET_DONT_RESOLVE)) == -1) {
    fprintf(stderr, "[!] Could not resolve IP address\n");
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  seq = 1;
  if (libnet_build_icmpv4_echo(ICMP_ECHO, 0, 0, id, seq, \
        NULL, 0, l, 0) == -1) {
    fprintf(stderr, "[!] Could not build ICMP header %s\n", \
        libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  if (libnet_autobuild_ipv4(LIBNET_IPV4_H+\
        LIBNET_ICMPV4_ECHO_H, IPPROTO_ICMP, daddr, l) == -1) {
    fprintf(stderr, "[!] Could not build IPv4 header: %s\n", \
        libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  if ((bytes_written = libnet_write(l)) != -1) {
      printf("[-] %d Bytes written.\n", bytes_written);
  } else {
    fprintf(stderr, "[!] Could not write packet: %s\n", \
        libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  libnet_destroy(l);
  return 0;
}

#ifndef DEV_H
#define DEV_H
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//=============================================================================
// Function pcap_finddevice: lists all available network devices with a IPv4
// address.
// Returns: pointer to a string containing the network device name.
//=============================================================================

char *
pcap_finddevice() {
  int i, input = 0, devnum = 0;
  pcap_if_t *alldevs, *dev;
  pcap_addr_t *addr;
  char errbuf[PCAP_ERRBUF_SIZE], *devname;

  printf("[-] Looking up devices...\n");
  /* find all devices */
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "[!] pcap_findalldevs: %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  /* list only network devices */
  printf("    %-19s | %-16s | %-16s | Description\n", "Name", "Address", "Mask");
  for (dev = alldevs; dev; dev = dev->next)
  for (addr = dev->addresses; addr; addr = addr->next)
    if (addr->addr->sa_family == AF_INET) {
      printf("[%d] %-19s | ", devnum++, dev->name);
      printf("%-16s | ", inet_ntoa(((struct sockaddr_in *)addr->addr)->sin_addr));
      printf("%-16s | ", inet_ntoa(((struct sockaddr_in *)addr->netmask)->sin_addr));
      if (dev->description != NULL)
        printf("%s\n", dev->description);
      else
        printf("No description available\n");
      break;
    }

  /* let user choose the device */
  printf("[+] Enter device number: ");
  scanf("%d", &input);

  /* no funny business */
  if (input < 0 || input >= devnum) {
    /* return null pointer - meaning no device selected */
    return  NULL;
  }

  /* get device name */
  for (i = 0, dev = alldevs; i < input; i++, dev = dev->next);

  /* allocate buffer, clear memory and copy dev name */
  if ((devname = (char *) malloc(sizeof(char)*(strlen(dev->name) + 1))) == NULL) {
    fprintf(stderr, "[!] malloc: couldn't allocate memory for device name\n");
    exit(EXIT_FAILURE);
  }
  bzero(devname, (strlen(dev->name) + 1));
  strncpy(devname, dev->name, strlen(dev->name));

  pcap_freealldevs(alldevs);
  return devname;      
}
#endif

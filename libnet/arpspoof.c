#include <libnet.h>
#include "../pcap/device.h"

int 
main(void) {
  char *devname;

  while ((devname = pcap_finddevice()) == NULL) {
    printf("[!] Please enter a valid device number!\n");
  }
  printf("[-] Using device: \'%s\'\n", devname);
  free(devname);
  return 0;
}

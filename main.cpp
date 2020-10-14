

#include "arp_spoofing.h"

void usage() {
  printf(
      "syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> "
      "<target ip 2> ...]\n");
  printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
  if (argc < 4 || argc & 1) {
    usage();
    return -1;
  }

  // get handle
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
    return -1;
  }

  // arp spoofing
  int res;
  ArpSpoofing* arpSpoofing;
  while (1) {
    for (int i = 2; i < argc; i += 2) {
      Ip sender_ip = Ip(argv[i]);
      Ip target_ip = Ip(argv[i + 1]);
      printf("try arp spoofing (%s -> %s)\n", std::string(sender_ip).c_str(),
             std::string(target_ip).c_str());
      res = arpSpoofing->arp_spoofing(dev, handle, sender_ip, target_ip);
      printf("========================================\n");
      if (res < 0) {
        printf("fail arp spoofing (%s -> %s)\n", std::string(sender_ip).c_str(),
               std::string(target_ip).c_str());
        return -1;
      } else {
        printf("success arp spoofing (%s -> %s)\n",
               std::string(sender_ip).c_str(), std::string(target_ip).c_str());
      }
      printf("========================================\n");
    }
  }
  pcap_close(handle);
  return 0;
}

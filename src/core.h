#ifndef _CORE_H
#define _CORE_H

#include <net/if.h>

#define IPV4SIZ 16
#define DEBUG

struct config {
  // mutual in server and client
  char tun_name[IFNAMSIZ];
  char tun_ip_addr[IPV4SIZ];
  char tun_netmask[IPV4SIZ];
  unsigned int port;
  char ip[IPV4SIZ];

  // client specific
  char server_tun_ip_addr[IPV4SIZ];
};

#endif

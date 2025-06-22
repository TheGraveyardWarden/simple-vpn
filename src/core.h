#ifndef _CORE_H
#define _CORE_H

#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>

#define IPV4SIZ 16
#define DEBUG

#define ROUTE_NETMASK_ENV "RT_NETMASK"
#define ROUTE_GATEWAY_ENV "RT_GATEWAY"
#define ROUTE_DEV_ENV			"RT_DEV"

struct config {
  // mutual in server and client
  char tun_name[IFNAMSIZ];
  char tun_ip_addr[IPV4SIZ];
  char tun_netmask[IPV4SIZ];
  unsigned int port;
  char ip[IPV4SIZ];

  // client specific
  char server_tun_ip_addr[IPV4SIZ];
  struct {
		char netmask[IPV4SIZ];
		char gateway[IPV4SIZ];
		char dev[IFNAMSIZ];
  } route_cfg;
};

#ifdef DEBUG
static void debug(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  printf(fmt, ap);
  va_end(ap);
}
#else
#define debug(...)
#endif

#endif

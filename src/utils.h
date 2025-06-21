#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct config;
struct sockaddr_in;
struct rtentry;

struct route
{
  const char *dst, *netmask, *gateway, *dev;
  unsigned int flags;
};

void route_print(struct route *rt);

#define SERVER 0x001 // server mode
#define CLIENT 0x002 // client mode

void exit_usage(char *bin, int mode);
int validate_ipv4(const char *ip);
int tun_alloc(const char *name, short flags, char persist, const char *ip, const char *netmask);
int sock_create(int domain, int type, int prot, const char *ip, unsigned int port, int backlog);
int sock_connect(int domain, int type, int prot, const char *ip, unsigned int port);
int parse_args(int argc, char *argv[], struct config *config, int mode);
int set_nonblocking(int fd);
int sockaddr_in_data(struct sockaddr_in *sin, int domain, const char *ip, unsigned int port);
int rtentry_data(struct rtentry *rte, struct route *rt);
int add_client_routes(struct config *cfg);
int logger(const char *name, const char *buff, unsigned int size);
int read_buff(int fd, void *buff, unsigned int size); // reads exactly size bytes
int read_buff2(int fd, void *buff, unsigned int size); // read upto size bytes
int read_u32(int fd, uint32_t *u32);
int write_u32(int fd, uint32_t x);
int write_buff(int fd, const void *buff, size_t size);

#define VALIDATE_IPV4(ip) \
  if (validate_ipv4((ip)) < 0) { printf("invalid ip address: %s\n", optarg); exit(-1); }

#endif

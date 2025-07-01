#include "utils.h"
#include "core.h"
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/route.h>

#define mode2defaults(mode, defaults_p)\
if      (mode == SERVER) (defaults_p) = &server_config;\
else if (mode == CLIENT) (defaults_p) = &client_config;\
else\
{\
  printf("mode should be either server or client: %d\n", mode);\
  exit(-1);\
}

static struct option options[] = {
  { "interface",      required_argument, 0, 'i' },
  { "addr",           required_argument, 0, 'a' },
  { "netmask",        required_argument, 0, 'n' },
  { "port",           required_argument, 0, 'p' },
  { "ip",             required_argument, 0, 'l' },
  { "server-tun-ip",  required_argument, 0, 's' },
  { "tunnel-range",   required_argument, 0, 't' },
  { "help",           no_argument,       0, 'h' },
  {  0,               0                , 0,  0  }
};

static struct config server_config = {
  .tun_name = "tun0",
  .tun_ip_addr = "10.0.0.1",
  .tun_netmask = "255.255.255.0",
  .port = 1337,
  .ip = "0.0.0.0"
};

static struct config client_config = {
  .tun_name = "tun1",
  .tun_ip_addr = "10.0.0.2",
  .tun_netmask = "255.255.255.0",
  .port = 1337,
  .ip = "0.0.0.0",
  .server_tun_ip_addr = "10.0.0.1",
	.route_cfg = {
		.netmask = "255.255.255.255",
		.gateway = "192.168.1.1",
		.dev = "wlan0"
	},
  .tunnel_range = {
    .ip = "\0",
    .netmask = "\0"
  }
};

void exit_usage(char *bin, int mode)
{
  struct config *defaults;

  mode2defaults(mode, defaults);

  printf("usage: %s [OPTIONS]\n", bin);
  printf("\nOPTIONS:\n");
  printf("\t-i, --interface:\ttun interface name (default: %s)\n", defaults->tun_name);
  printf("\t-a, --addr:\t\tipv4 address of tun interface (default: %s)\n", defaults->tun_ip_addr);
  printf("\t-n, --netmask:\t\tnetmask of tun interface (default: %s)\n", defaults->tun_netmask);
  printf("\t-p, --port:\t\tserver socket port (default: %u)\n", defaults->port);
  printf("\t-l, --ip:\t\tserver socket ip (default: %s)\n", defaults->ip);
  if (mode == CLIENT)
  {
    printf("\t-s, --server-tun-ip:\tserver tun ip address (default: %s)\n", defaults->server_tun_ip_addr);
    printf("\t-t, --tunnel-range:\tonly tunnel a specific range. should be a valid cidr (e.g 192.168.1.0/24). disabled by default\n");
  }
  printf("\t-h, --help:\t\tshows this help message\n");

	if (mode == CLIENT) {	
		printf("\nENVIRONMENT VARIABLES:\n");
		printf("\t%s:\t\tnetmask of local network (default: %s)\n", ROUTE_NETMASK_ENV, defaults->route_cfg.netmask);
		printf("\t%s:\t\tgateway of local network (default: %s)\n", ROUTE_GATEWAY_ENV, defaults->route_cfg.gateway);
		printf("\t%s:\t\t\tdev of local network (default: %s)\n", ROUTE_DEV_ENV, defaults->route_cfg.dev);
	}

  exit(-1);
}

int validate_ipv4(const char *ip)
{
  struct in_addr addr;

  memset(&addr, 0, sizeof(struct in_addr));

  if (inet_pton(AF_INET, ip, &addr) == 0)
    return -1;

  return 0;
}

int tun_alloc(const char *name,
              short flags,
              char persist,
              const char *ip,
              const char *netmask)
{
  int tun_fd, sock_fd;
  struct ifreq ifr;
  struct sockaddr_in sin;

  memset(&ifr, 0, sizeof(ifr));
  memset(&sin, 0, sizeof(sin));

  if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0)
  {
    perror("failed to open tun device");
    return -1;
  }

  strncpy(ifr.ifr_name, name, IFNAMSIZ);
  ifr.ifr_flags = flags;
  if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0)
  {
    perror("failed to allocate tun device");
    goto tun_cleanup;
  }

  if (ioctl(tun_fd, TUNSETPERSIST, persist) < 0)
  {
    perror("failed to set persist of tun device");
    goto tun_cleanup;
  }

  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("failed to create socket");
    goto tun_cleanup;
  }

  if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0)
  {
    perror("failed to read interface flags");
    goto sock_cleanup;
  }

  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0)
  {
    perror("failed to set interface flags");
    goto sock_cleanup;
  }

  if (sockaddr_in_data(&sin, AF_INET, ip, 0) < 0)
  {
    perror("failed to parse ip address");
    printf("ip: %s\n", ip);
    goto sock_cleanup;
  }

  ifr.ifr_addr = *(struct sockaddr*)&sin;
  if (ioctl(sock_fd, SIOCSIFADDR, &ifr) < 0)
  {
    perror("failed to set interface ip address");
    goto sock_cleanup;
  }

  if (sockaddr_in_data(&sin, AF_INET, netmask, 0) < 0)
  {
    perror("failed to parse ip address");
    printf("ip: %s\n", netmask);
    goto sock_cleanup;
  }

  ifr.ifr_addr = *(struct sockaddr*)&sin;
  if (ioctl(sock_fd, SIOCSIFNETMASK, &ifr) < 0)
  {
    perror("failed to set interface netmask");
    goto sock_cleanup;
  }

  if (set_nonblocking(tun_fd) < 0)
  {
    perror("set_nonblocking() tun_fd");
    goto sock_cleanup;
  }

  close(sock_fd);
  return tun_fd;

tun_cleanup:
  close(tun_fd);
  return -1;

sock_cleanup:
  close(tun_fd);
  close(sock_fd);
  return -1;
}

int sock_create(int domain, int type, int prot, const char *ip, unsigned int port, int backlog)
{
  int sock_fd, optval = 1;
  struct sockaddr_in sin;

  memset(&sin, 0, sizeof(sin));

  if ((sock_fd = socket(domain, type, prot)) < 0)
  {
    perror("failed to open socket");
    return -1;
  }

  if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0)
  {
    perror("failed to set sock reuse port");
    goto sock_cleanup;
  }

  if (sockaddr_in_data(&sin, domain, ip, port) < 0)
  {
    perror("failed to parse ip");
    printf("ip: %s\n", ip);
    goto sock_cleanup;
  }

  if (bind(sock_fd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
  {
    perror("failed to bind socket");
    goto sock_cleanup;
  }

  if (listen(sock_fd, backlog) < 0)
  {
    perror("failed to listen");
    goto sock_cleanup;
  }

  /*
  if (set_nonblocking(sock_fd) < 0)
  {
    perror("failed to set sock_fd to non blocking mode");
    goto sock_cleanup;
  }
  */

  return sock_fd;

sock_cleanup:
  close(sock_fd);
  return -1;
}

int sock_connect(int domain, int type, int prot, const char *ip, unsigned int port)
{
  int sock_fd;
  struct sockaddr_in sin;

  if ((sock_fd = socket(domain, type, prot)) < 0)
  {
    perror("failed to open socket");
    return -1;
  }

  if (sockaddr_in_data(&sin, domain, ip, port) < 0)
  {
    perror("sockaddr_in_data() in sock_connect()");
    goto sock_cleanup;
  }

  if (connect(sock_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
  {
    perror("connect() in sock_connect()");
    goto sock_cleanup;
  }

  if (set_nonblocking(sock_fd) < 0)
  {
    perror("set_nonblocking() in sock_connect()");
    goto sock_cleanup;
  }

  return sock_fd;

sock_cleanup:
  close(sock_fd);
  return -1;
}

int parse_args(int argc, char *argv[], struct config *config, int mode)
{
  struct config *defaults;
  int opt;
  int optind = 0;
	const char *env = NULL;

  mode2defaults(mode, defaults);

  while ((opt = getopt_long(argc, argv, "i:a:n:p:l:s:t:h", options, &optind)) != -1)
  {
    switch(opt)
    {
      case 'i':
        strncpy(config->tun_name, optarg, IFNAMSIZ);
        break;
      case 'a':
        VALIDATE_IPV4(optarg);
        strncpy(config->tun_ip_addr, optarg, IPV4SIZ);
        break;
      case 'n':
        VALIDATE_IPV4(optarg);
        strncpy(config->tun_netmask, optarg, IPV4SIZ);
        break;
      case 'p':
        config->port = (unsigned int)atoi(optarg);

        if (config->port <= 0 || config->port >= 65535)
        {
          printf("invalid port: %u (%d)\n", config->port, config->port);
          return -1;
        }
        break;
      case 'l':
        VALIDATE_IPV4(optarg);
        strncpy(config->ip, optarg, IPV4SIZ);
        break;
      case 's':
        if (mode == SERVER)
        {
          printf("[!] Warning: -s, --server-tun-ip will be ignored!\n");
          break;
        }

        VALIDATE_IPV4(optarg);
        strncpy(config->server_tun_ip_addr, optarg, IPV4SIZ);
        break;
      case 't':
        if (mode == SERVER)
        {
          printf("[!] Warning: -t, --tunnel-range will be ignored!\n");
          break;
        }

        char *cidr = NULL;
        int i, netmask_shift;
        uint32_t netmask = 0;

        cidr = strchr(optarg, '/');
        if (cidr == NULL)
        {
          printf("wrong cidr: %s\n", optarg);
          return -1;
        }

        *cidr++ = 0;

        VALIDATE_IPV4(optarg);
        strncpy(config->tunnel_range.ip, optarg, IPV4SIZ);

        netmask_shift = atoi(cidr);
        if (netmask_shift <= 0 || netmask_shift > 32)
        {
          printf("wrong netmask: %d\n", netmask_shift);
          return -1;
        }

        for (i = 0; i < netmask_shift; i++)
        {
          netmask |= 1 << (31-i);
        }

        netmask = htonl(netmask);

        if (inet_ntop(AF_INET, (const void *)&netmask, config->tunnel_range.netmask, IPV4SIZ) == NULL)
        {
          perror("inet_ntop()");
          return -1;
        }
        break;
      case 'h':
      default:
        exit_usage(argv[0], mode);
    }
  }

  if (*(config->tun_name) == 0)
    strncpy(config->tun_name, defaults->tun_name, IFNAMSIZ);

  if (*(config->tun_ip_addr) == 0)
    strncpy(config->tun_ip_addr, defaults->tun_ip_addr, IPV4SIZ);

  if (*(config->tun_netmask) == 0)
    strncpy(config->tun_netmask, defaults->tun_netmask, IPV4SIZ);

  if (config->port == 0)
    config->port = defaults->port;

  if (*(config->ip) == 0)
    strncpy(config->ip, defaults->ip, IPV4SIZ);

	if (mode == CLIENT) {
	  if (*(config->server_tun_ip_addr) == 0)
  	  strncpy(config->server_tun_ip_addr, defaults->server_tun_ip_addr, IPV4SIZ);

		if ((env = getenv(ROUTE_NETMASK_ENV)) == NULL)
			strncpy(config->route_cfg.netmask, defaults->route_cfg.netmask, IPV4SIZ);
    else
    {
      VALIDATE_IPV4(env);
			strncpy(config->route_cfg.netmask, env, IPV4SIZ);
    }

		if ((env = getenv(ROUTE_GATEWAY_ENV)) == NULL)
			strncpy(config->route_cfg.gateway, defaults->route_cfg.gateway, IPV4SIZ);
    else
    {
      VALIDATE_IPV4(env);
			strncpy(config->route_cfg.gateway, env, IPV4SIZ);
    }

		if ((env = getenv(ROUTE_DEV_ENV)) == NULL)
			strncpy(config->route_cfg.dev, defaults->route_cfg.dev, IFNAMSIZ);
    else
			strncpy(config->route_cfg.dev, env, IFNAMSIZ);
	}

  return 0;
}

int set_nonblocking(int fd)
{
  int flags;

  if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
    flags = 0;

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
  {
    perror("failed to set sock_fd to non blocking mode");
    return -1;
  }

  return 0;
}

int sockaddr_in_data(struct sockaddr_in *sin, int domain, const char *ip, unsigned int port)
{
  sin->sin_family = domain;
  sin->sin_port = htons(port);
  if (inet_pton(domain, ip, &sin->sin_addr) < 1)
  {
    perror("inet_pton()");
    return -1;
  }

  return 0;
}

int rtentry_data(struct rtentry *rte, struct route *rt)
{
  struct sockaddr_in sin;

  if (!rte || !rt)
  {
    printf("route entry or route data should not be NULL\n");
    return -1;
  }

  memset(rte, 0, sizeof(struct rtentry));

  if (sockaddr_in_data(&sin, AF_INET, rt->dst, 0) < 0)
  {
    perror("sockaddr_in_data(dst_ip) in rtentry_data");
    return -1;
  }
  rte->rt_dst = *(struct sockaddr *)&sin;

  if (sockaddr_in_data(&sin, AF_INET, rt->netmask, 0) < 0)
  {
    perror("sockaddr_in_data(netmask_ip) in rtentry_data");
    return -1;
  }
  rte->rt_genmask = *(struct sockaddr *)&sin;

  if (sockaddr_in_data(&sin, AF_INET, rt->gateway, 0) < 0)
  {
    perror("sockaddr_in_data(gateway_ip) in rtentry_data");
    return -1;
  }
  rte->rt_gateway = *(struct sockaddr *)&sin;

  rte->rt_flags = rt->flags;
  rte->rt_dev = (char *)rt->dev;
  rte->rt_metric = 0;

  return 0;
}

int routes_add(struct route *rts, size_t size)
{
  if (rts == NULL)
  {
    errno = EINVAL;
    return -1;
  }

  struct rtentry rte;
  int i, sockfd;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("socket() in add_client_routes()");
    return -1;
  }

  for (i = 0; i < size; i++)
  {
    if (rtentry_data(&rte, &rts[i]) < 0)
    {
      printf("could not add route\n");
      route_print(&rts[i]);
      goto sock_cleanup;
    }
    if (ioctl(sockfd, SIOCADDRT, &rte) < 0)
    {
      perror("ioctl() in route_add()");
      printf("could not add route\n");
      route_print(&rts[i]);
      goto sock_cleanup;
    }
  }

  close(sockfd);
  return 0;

sock_cleanup:
  close(sockfd);
  return -1;
}

int add_client_routes(struct config *cfg)
{
  struct route rts[3];
  size_t size = 3;

  rts[0] = (struct route){
    .dst = (const char *)cfg->ip,
    .netmask = (const char *)cfg->route_cfg.netmask,
    .gateway = (const char *)cfg->route_cfg.gateway,
    .dev = (const char *)cfg->route_cfg.dev,
    .flags = RTF_UP | RTF_GATEWAY | RTF_HOST
  };

  if (cfg->tunnel_range.ip[0])
  {
    size = 2;

    rts[1] = (struct route){
      .dst = cfg->tunnel_range.ip,
      .netmask = cfg->tunnel_range.netmask,
      .gateway = (const char *)cfg->server_tun_ip_addr,
      .dev = (const char *)cfg->tun_name,
      .flags = RTF_UP | RTF_GATEWAY
    };
  }
  else
  {
    rts[1] = (struct route){
      .dst = "0.0.0.0",
      .netmask = "128.0.0.0",
      .gateway = (const char *)cfg->server_tun_ip_addr,
      .dev = (const char *)cfg->tun_name,
      .flags = RTF_UP | RTF_GATEWAY
    };
  
    rts[2] = (struct route){
      .dst = "128.0.0.0",
      .netmask = "128.0.0.0",
      .gateway = (const char *)cfg->server_tun_ip_addr,
      .dev = (const char *)cfg->tun_name,
      .flags = RTF_UP | RTF_GATEWAY
    };
  }

  if (routes_add(rts, size) < 0)
  {
    perror("routes_add()");
    return -1;
  }

  return 0;
}

void route_print(struct route *rt)
{
  printf("route\n{\n\tdst: %s,\n\tnetmask: %s,\n\tgateway: %s,\n\tdev: %s\n}\n",
          rt->dst, rt->netmask, rt->gateway, rt->dev);
}

int logger(const char *name, const char *buff, unsigned int size)
{
	FILE *f;
	int i;

  if ((f = fopen(name, "w")) == NULL)
  {
    perror("fopen()");
    printf("tried to open %s\n", name);
    return -1;
  }

	for (i = 0; i < size; i++) {
		if (fprintf(f, "%02x ", (unsigned char)buff[i]) < 0) {
			perror("fprintf");
			fclose(f);
			return -1;
		}
	}

  fprintf(f, "\n");

  printf("successfully logged to %s\n", name);
  fclose(f);
  return 0;
}

int read_buff(int fd, void *buff, unsigned int size)
{
  int nread;
  errno = 0;

begin_read:
  nread = read(fd, buff, size);

  if (nread >= 0) {
    if (nread != size) {
      errno = EAGAIN;
    }

    return nread;
  }
  else
  {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return 0;

    if (errno == EINTR)
      goto begin_read;

    perror("read()");
    return -1;
  }

  // never reaches
  return nread;
}

int read_buff2(int fd, void *buff, unsigned int size)
{
  int nread;
  unsigned int readn = 0;
  errno = 0;

begin_read:
  while ((nread = read(fd, buff+readn, size-readn)) > 0)
  {
    readn += (unsigned int)nread;

    if (readn != size)
      continue;

    goto done;
  }

  if (readn == 0 || errno == EINTR)
    goto begin_read;

  if (nread < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
  {
    perror("read()");
    return -1;
  }

done:
  return (int)readn;
}

int read_blocking(int fd, void *buff, unsigned int size)
{
  int nread;
  unsigned int readn = 0;
  errno = 0;

begin_read:
  while ((nread = read(fd, buff+readn, size-readn)) > 0)
  {
    readn += (unsigned int)nread;

    if (readn != size)
      continue;

    goto done;
  }

  if (readn == 0)
    goto begin_read;

  if (nread < 0)
  {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
      goto begin_read;

    perror("read()");
    return -1;
  }

done:
  return (int)readn;
}

int read_u32(int fd, uint32_t *u32)
{
  int nread;

  if ((nread = read_blocking(fd, u32, sizeof(*u32))) < 0)
  {
    printf("read_buff(fd, u32)\n");
    return -1;
  }

  *u32 = ntohl(*u32);

  return nread;
}

int write_buff(int fd, const void *buff, size_t size)
{
  ssize_t nwrite, ret = 0;

_write:
  while ((nwrite = write(fd, buff, size)) > 0)
  {
		ret += nwrite;
    if (nwrite != size)
    {
      buff += nwrite;
			size -= nwrite;
      continue;
    }
    goto done;
  }

	if (nwrite < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
    {
      printf("WRITE IS BLOCKING\n");
			goto _write;
    }

		return (int)nwrite;
	}

  if (!nwrite) return (int)nwrite;

	debug("write finished in a funny way\n");
	debug("errno: %s\n", strerror(errno));
	debug("nwrite: %zd, size: %ud\n", nwrite, size);

done:
  return (int)ret;
}

int write_u32(int fd, uint32_t x)
{
	uint32_t net_x = htonl(x);

	return write_buff(fd, &net_x, sizeof(uint32_t));
}


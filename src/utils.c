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
// baraye parse kardane argument ha 
// onaei ke argument mikhan masalan -l ke bayad ip vared konim
// ya masalan -h ke baadesh chizi nemikihad vared konim
static struct option options[] = {
  { "interface",      required_argument, 0, 'i' },
  { "addr",           required_argument, 0, 'a' },
  { "netmask",        required_argument, 0, 'n' },
  { "port",           required_argument, 0, 'p' },
  { "ip",             required_argument, 0, 'l' },
  { "server-tun-ip",  required_argument, 0, 's' },
  { "help",           no_argument,       0, 'h' },
  {  0,               0                , 0,  0  }
};

// in do ta baraye neveshtan config samt client va server estefade mishavand
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
  .server_tun_ip_addr = "10.0.0.1"
};


// This will print the 
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
    printf("\t-s, --server-tun-ip:\tserver tun ip address (default: %s)\n", defaults->server_tun_ip_addr);
  printf("\t-h, --help:\t\tshows this help message\n");

  exit(-1);
}

//in tabe check mikone bebinam ipv4 doroste ya na 
int validate_ipv4(const char *ip)
{
  //in built in linux ((man sockaddr))
  struct in_addr addr;

  memset(&addr, 0, sizeof(struct in_addr));

  // built in ast ((man inet_pton)) pton== presentation(text ya string) to network(yani binery)
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
  // in do ta built in hastand ifreq is in netdevice
  struct ifreq ifr;
  struct sockaddr_in sin;
  // ifr and sin ro sefr mikone
  memset(&ifr, 0, sizeof(ifr));
  memset(&sin, 0, sizeof(sin));

  // it give you a file descriptor for tun (ye tun interface misaze)
  if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0)
  {
    perror("failed to open tun device");
    return -1;
  }

  //in flag ha moshkhas konandeye modele interface( tun ya tap) hastand
  strncpy(ifr.ifr_name, name, IFNAMSIZ);
  ifr.ifr_flags = flags;
  //TUNSETIFF  : tun set interface flag   (be in migan request)  - inja flag va name ro set mikonim
  if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0)
  {
    perror("failed to allocate tun device");
    goto tun_cleanup;
  }
  // inja persist ro set mikone
  if (ioctl(tun_fd, TUNSETPERSIST, persist) < 0)
  {
    perror("failed to set persist of tun device");
    goto tun_cleanup;
  }
  // socket ham built in ast -  inja ye socket ipv4 va tcp sakht
  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("failed to create socket");
    goto tun_cleanup;
  }
  // inja flag haye interface(tun) ra migirad vali dar if badi set mikonad
  if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr) < 0)
  {
    perror("failed to read interface flags");
    goto sock_cleanup;
  }
  // inja flag haye interface(tun) ra set mikonim
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr) < 0)
  {
    perror("failed to set interface flags");
    goto sock_cleanup;
  }

  // inja ip va port ro az halate text mibarim be halate network va on ro dar sin mirizim
  if (sockaddr_in_data(&sin, AF_INET, ip, 0) < 0)
  {
    perror("failed to parse ip address");
    printf("ip: %s\n", ip);
    goto sock_cleanup;
  }

  // The first line assigns the address of the sin structure (which conatins the desired
  // ip address) to the ifr_addr field of the ifr structure 
  // and in if statement sets the ioctl system call to set the IP address of the network 
  // interface. -- SIOCSIFADDR This command tells the kernel to set the IP address of the interface.
  // dar vaghe if statement ma inja ip ro set mikone hamin!
  ifr.ifr_addr = *(struct sockaddr*)&sin;
  if (ioctl(sock_fd, SIOCSIFADDR, &ifr) < 0)
  {
    perror("failed to set interface ip address");
    goto sock_cleanup;
  }

  // inja netmask va port ro az halate text mibarim be halate network va on ro dar sin mirizim
  if (sockaddr_in_data(&sin, AF_INET, netmask, 0) < 0)
  {
    perror("failed to parse ip address");
    printf("ip: %s\n", netmask);
    goto sock_cleanup;
  }
  // shabihe hamon balaei hast vali baraye netmask
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


// in fucntioin baraye socket samt server ast
int sock_create(int domain, int type, int prot, const char *ip, unsigned int port, int backlog)
{
  //sock_fd is socket file descriptor
  int sock_fd, optval = 1;
  struct sockaddr_in sin;

  memset(&sin, 0, sizeof(sin));

  //inja socket ra misazim
  // domain = (ipv4 or ipv6) --  type ma (tcp ya udp)
  // socket port haye ertebatiye ma beine server va client ra
  if ((sock_fd = socket(domain, type, prot)) < 0)
  {
    perror("failed to open socket");
    return -1;
  }

  // setsockopt = (set socket options)   ye seri tanzimat ra baraye socket tanzim mikone
  // SO_REUSEPORT ==  ba komake in agar yek port bind shode bashe mishe dobare estefade
  // kard azash 
  if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) < 0)
  {
    perror("failed to set sock reuse port");
    goto sock_cleanup;
  }
  // inja faghat ip va port ra set mikonim
  if (sockaddr_in_data(&sin, domain, ip, port) < 0)
  {
    perror("failed to parse ip");
    printf("ip: %s\n", ip);
    goto sock_cleanup;
  }
  // bind yek ip va port ro be on socket ke sakhtim takhsis  midim(bind mikonim) 
  if (bind(sock_fd, (struct sockaddr*)&sin, sizeof(sin)) < 0)
  {
    perror("failed to bind socket");
    goto sock_cleanup;
  }
  // ba in kar socket ro faal mikonim ke betone connection accept kone
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

// in fucntioin baraye socket samt client ast
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
  // Purpose: This line attempts to connect the socket identified by 
  // sock_fd to the address specified in the sin structure.
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

// The parse_args function is responsible for parsing command-line arguments  provided 
// to the program and populating a configuration structure (struct config) with the parsed values
int parse_args(int argc, char *argv[], struct config *config, int mode)
{
  struct config *defaults;
  int opt;
  int optind = 0;

  mode2defaults(mode, defaults);

  while ((opt = getopt_long(argc, argv, "i:a:n:p:l:s:h", options, &optind)) != -1)
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

  if (*(config->server_tun_ip_addr) == 0)
    strncpy(config->server_tun_ip_addr, defaults->server_tun_ip_addr, IPV4SIZ);

  return 0;
}

// tozihat dakhele barge
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

// ip va port ro az text format(presentation) be binary(network) format tabdil mikonad
// har ja sockaddr_in didim yani ip va port dar halate network(binary)
// domain ipv4 ya ipv6 bodan ra taeen mikonad
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

// baraye inja to utils.h struct route ro bebin
// inja miad struct route ro mirize toye rtentry(route entry)
int rtentry_data(struct rtentry *rte, struct route *rt)
{
  struct sockaddr_in sin;
  //age harkom khali bodane error mide
  if (!rte || !rt)
  {
    printf("route entry or route data should not be NULL\n");
    return -1;
  }
  // inja omadim mohtaviat rtenry ro clear kardim
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
  // hamon interface ast ( to terminal bezan routn -n)
  rte->rt_dev = (char *)rt->dev;
  // in haman metrik routing table ast
  rte->rt_metric = 0;

  return 0;
}

// config vorodi inja ro toye pars args misazim
int add_client_routes(struct config *cfg)
{
  struct rtentry rte;
  struct route rt;
  int sockfd;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("socket() in add_client_routes()");
    return -1;
  }
  //in route baraye masiryabie packet hayei ast ke be server vpn 
  // miravand -- in packet ha nabayad vared tun interface shavand
  // be khatere hamin dev ma wlp4s0 ast ke default system ast
  rt.dst = (const char *)cfg->ip;
  // be in dalil ke dar inja faghat yek ip darim va an ip server 
  // ast ino minevisim
  rt.netmask = "255.255.255.255";
  rt.gateway = "192.168.43.1"; 
  rt.dev = "wlp4s0"; 
  rt.flags = RTF_UP | RTF_GATEWAY | RTF_HOST; // or kardan chand flage ma ke darim
  if (rtentry_data(&rte, &rt) < 0)
  {
    printf("could not add route\n");
    route_print(&rt);
    goto sock_cleanup;
  }
  if (ioctl(sockfd, SIOCADDRT, &rte) < 0)
  {
    perror("ioctl() in add_client_routes()");
    printf("could not add route\n");
    route_print(&rt);
    goto sock_cleanup;
  }

  // in do route  baes mishavand tamam packet haye ma be jaye an ke be
  // wlp4s0 beravand be interface tun miravand 
  // dar vaghe in ja packet ha ra bejaye ferestadan be 
  // network(maghsade vaghei) be client vpn miferestad 
  rt.dst = "0.0.0.0";
  rt.netmask = "128.0.0.0";
  rt.gateway = (const char *)cfg->server_tun_ip_addr;
  rt.dev = (const char *)cfg->tun_name;
  rt.flags = RTF_UP | RTF_GATEWAY;
  if (rtentry_data(&rte, &rt) < 0)
  {
    printf("could not add route\n");
    route_print(&rt);
    goto sock_cleanup;
  }
  if (ioctl(sockfd, SIOCADDRT, &rte) < 0)
  {
    perror("ioctl() in add_client_routes()");
    printf("could not add route\n");
    route_print(&rt);
    goto sock_cleanup;
  }

  rt.dst = "128.0.0.0";
  rt.netmask = "128.0.0.0";
  rt.gateway = (const char *)cfg->server_tun_ip_addr;
  rt.dev = (const char *)cfg->tun_name;
  rt.flags = RTF_UP | RTF_GATEWAY;
  if (rtentry_data(&rte, &rt) < 0)
  {
    printf("could not add route\n");
    route_print(&rt);
    goto sock_cleanup;
  }
  if (ioctl(sockfd, SIOCADDRT, &rte) < 0)
  {
    perror("ioctl() in add_client_routes()");
    printf("could not add route\n");
    route_print(&rt);
    goto sock_cleanup;
  }

  close(sockfd);

  return 0;

  sock_cleanup:
    close(sockfd);
    return -1;
}
// literally faghat route ro print mikone
void route_print(struct route *rt)
{
  printf("route\n{\n\tdst: %s,\n\tnetmask: %s,\n\tgateway: %s,\n\tdev: %s\n}\n",
          rt->dst, rt->netmask, rt->gateway, rt->dev);
}

/*
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
*/
// fd ham mitone tun bashe ham socket 
// dar samt server va client 
int read_buff(int fd, void *buff, unsigned int size)
{
  //nread = number read == tedad byte haei ke mikhone
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
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        goto begin_read;

      perror("read()");
      return -1;
    }

    done:
      return (int)readn;
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

int read_u32(int fd, uint32_t *u32)
{
  int nread;

  if ((nread = read_buff(fd, u32, sizeof(*u32))) < 0)
  {
    printf("read_buff(fd, u32)\n");
    return -1;
  }

  // ntohl = network to host long
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
        goto _write;

      return (int)nwrite;
    }

  if (!nwrite) return (int)nwrite;

  #ifdef DEBUG
    printf("write finished in a funny way\n");
    printf("errno: %s\n", strerror(errno));
    printf("nwrite: %zd, size: %ud\n", nwrite, size);
  #endif

  done:
    return (int)ret;
}


//in function size buffer ma ro be halate network mibare va ono 
// miferesre be maghsad ma (fd ) che in maghsad samt server bashad 
// che samte client  -- htonl(host to network long)
int write_u32(int fd, uint32_t x)
{
	uint32_t net_x = htonl(x);

	return write_buff(fd, &net_x, sizeof(uint32_t));
}


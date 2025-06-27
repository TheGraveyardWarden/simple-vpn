#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "core.h"
#include "utils.h"
#include <linux/if_tun.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <errno.h>

#define MODE CLIENT

#define MAX_EVENTS 200
#define BUFFSZ 500*1024

int main(int argc, char *argv[])
{
  struct config config;
  struct epoll_event ev, events[MAX_EVENTS];
  int tun_fd, sock_fd, epfd, nwrite, nread, n, nfds;
  char *buff;
  uint32_t len;

	if ((buff = malloc(BUFFSZ)) == NULL) {
		perror("malloc");
		return -1;
	}

  memset(&config, 0, sizeof(struct config));

  if (parse_args(argc, argv, &config, MODE) < 0)
  {
    printf("failed to parse args\n");
    return -1;
  }

  if ((tun_fd = tun_alloc(config.tun_name,
                          IFF_TUN | IFF_NO_PI,
                          0,
                          config.tun_ip_addr,
                          config.tun_netmask)) < 0)
  {
    printf("failed to allocate tun device\n");
    return -1;
  }

  printf("allocated tun deivce\n");

  if (add_client_routes(&config) < 0)
  {
    printf("failed to add routes!\n");

  #ifdef DEBUG_CONFIG
      printf("config\n{\n\ttun_name: %s,\n\ttun_ip_addr: %s,\n\ttun_netmask: %s,\n\tport: %u,\n\tip: %s,\n\tserver_tun_ip_addr: %s\n\n}\n",
          config.tun_name, config.tun_ip_addr, config.tun_netmask, config.port, config.ip, config.server_tun_ip_addr);
  #endif

    return -1;
  }

  if ((sock_fd = sock_connect(AF_INET, SOCK_STREAM, 0, config.ip, config.port)) < 0)
  {
    perror("sock_connect()");
    return -1;
  }

  printf("connected to: %s:%u\n", config.ip, config.port);

  if ((epfd = epoll_create1(0)) < 0)
  {
    perror("epoll_create1()");
    return -1;
  }

  ev.events = EPOLLIN;
  ev.data.fd = sock_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock_fd, &ev) < 0)
  {
    perror("epoll_ctl() add on sock_fd");
    return -1;
  }

  ev.events = EPOLLIN;
  ev.data.fd = tun_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev) < 0)
  {
    perror("epoll_ctl() add on tun_fd");
    return -1;
  }

  while (1)
  {
    nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
    if (nfds < 0)
    {
      perror("epoll_wait()");
      return -1;
    }

    for (n = 0; n < nfds; n++)
    {
      // dar inja packet responsi ke az samt server amade ra mikhanim 
      // va an ra be tun midahim ta process shavad 
			if (events[n].data.fd == sock_fd)
			{
        // aval size ra migirim az server 
        nread = read_u32(sock_fd, &len);
        if (nread < 0)
        {
          printf("read_u32(client_fd, &len)\n");
          return -1;
        }
        // hala size ro darim va packet ro az server mikhonim 
        // mirizim to buffer 
        nread = read_buff(sock_fd, buff, len);
        if (nread < 0)
        {
          printf("read_buff(client_fd, buff, len)\n");
          return -1;
        }
        // hala darim buffer ro be tun midim baraye process
        nwrite = write_buff(tun_fd, buff, len);
        if (nwrite < 0)
        {
          perror("write_buff(tun_fd, buff, len)");
          return -1;
        }

      }
      // inja ma ebteda marhaleye aval ra ejra mikonim 
      // dakhele barge -- dar vaghe dar inja packet az tun interface
      // khande mishavad va be samte server ferestade mishavad
      else if (events[n].data.fd == tun_fd)
			{
        nread = read_buff2(tun_fd, buff, BUFFSZ);
        if (nread < 0)
        {
          printf("read_buff(tun_fd, buff, BUFFSZ)\n");
          return -1;
        }

        len = (uint32_t)nread;
				printf("sending len to server: %u\n", len);
        nwrite = write_u32(sock_fd, len);
        if (nwrite < 0)
        {
          perror("write_u32(client_fd, len)");
          return -1;
        }

        nwrite = write_buff(sock_fd, buff, len);
        if (nwrite < 0)
        {
          perror("write_buff(client_fd, buff, len)");
          return -1;
        }

      }
    }
  }

  close(tun_fd);
  close(sock_fd);
  close(epfd);
	free(buff);

	return 0;
}

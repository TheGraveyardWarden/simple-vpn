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
  char *sock_buff, *tun_buff;
  uint32_t tun_len, sock_len, stored_len;
  char paused = 0;

	if ((tun_buff = malloc(BUFFSZ)) == NULL) {
		perror("malloc");
		return -1;
	}

	if ((sock_buff = malloc(BUFFSZ)) == NULL) {
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
			if (events[n].data.fd == sock_fd)
			{
        if (paused)
          goto begin_read_buff;

        nread = read_u32(sock_fd, &sock_len);
        if (nread < 0)
        {
          printf("read_u32(sock_fd, &len)\n");
          return -1;
        }

begin_read_buff:
        printf("trying to read_buff from socket: stored_len: %u\tsock_len: %u\n", stored_len, sock_len);
        nread = read_buff(sock_fd, sock_buff+stored_len, sock_len-stored_len);

        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          paused = 1;
          stored_len += (uint32_t)nread;
          printf("we paused. stored_len: %u\tsock_len: %u\n", stored_len, sock_len);
          continue;
        }

        if (nread < 0)
        {
          printf("read_buff(sock_fd, buff, len)\n");
          return -1;
        }

        nwrite = write_buff(tun_fd, sock_buff, sock_len);
        if (nwrite < 0)
        {
          perror("write_buff(tun_fd, buff, len)");
          return -1;
        }

        stored_len = 0;
        paused = 0;
      }
      else if (events[n].data.fd == tun_fd)
			{
        nread = read_buff2(tun_fd, tun_buff, BUFFSZ);
        if (nread < 0)
        {
          printf("read_buff(tun_fd, buff, BUFFSZ)\n");
          return -1;
        }

        tun_len = (uint32_t)nread;
				printf("sending len to server: %u\n", tun_len);
        nwrite = write_u32(sock_fd, tun_len);
        if (nwrite < 0)
        {
          perror("write_u32(client_fd, len)");
          return -1;
        }

        nwrite = write_buff(sock_fd, tun_buff, tun_len);
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
	free(tun_buff);
	free(sock_buff);

	return 0;
}

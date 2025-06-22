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

#define MODE SERVER

#define MAX_EVENTS 200
#define BUFFSZ 500*1024

int main(int argc, char *argv[])
{
  struct config config;
  int tun_fd, sock_fd, client_fd, epfd, nfds, n, nread, nwrite;
  struct epoll_event ev, events[MAX_EVENTS];
  struct sockaddr_in addr;
  socklen_t addr_len;
  char client_ip[16], *tun_buff, *sock_buff;
  uint32_t tun_len, sock_len, stored_len = 0;

  if ((tun_buff = malloc(BUFFSZ)) == NULL)
  {
    perror("malloc(tun_buff)");
    return -1;
  }

  if ((sock_buff = malloc(BUFFSZ)) == NULL)
  {
    perror("malloc(sock_buff)");
    return -1;
  }

  memset(&config, 0, sizeof(struct config));
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr_len = sizeof(addr);

  if (parse_args(argc, argv, &config, MODE) < 0)
  {
    printf("failed to parse args!\n");
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

  if ((sock_fd = sock_create(AF_INET, SOCK_STREAM, 0, config.ip, config.port, 1)) < 0)
  {
    printf("failed to create socket\n");
    return -1;
  }

  printf("listening on %s:%u\n", config.ip, config.port);

  if ((client_fd = accept(sock_fd, (struct sockaddr *)&addr, &addr_len)) < 0)
  {
    perror("accept()");
    return -1;
  }

  if (set_nonblocking(client_fd) < 0)
  {
    perror("set_nonblocking() client_fd");
    return -1;
  }

  if (inet_ntop(AF_INET, &addr.sin_addr, client_ip, 16) == NULL)
  {
    perror("inet_pton()");
    return -1;
  }

  printf("%s:%d connected!!\n", client_ip, ntohs(addr.sin_port));

  if ((epfd = epoll_create1(0)) < 0)
  {
    perror("epoll_create1()");
    return -1;
  }

  ev.events = EPOLLIN;
  ev.data.fd = client_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev) < 0)
  {
    perror("epoll_ctl() add on client_fd");
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
      if (events[n].data.fd == client_fd)
      {
        if (stored_len)
          goto begin_read_buff;

        nread = read_u32(client_fd, &sock_len);
        if (nread < 0)
        {
          printf("read_u32(client_fd, &len)\n");
          return -1;
        }

begin_read_buff:
        nread = read_buff(client_fd, sock_buff+stored_len, sock_len-stored_len);

        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          stored_len = nread;
          continue;
        }

        if (nread < 0)
        {
          printf("read_buff(client_fd, buff, len)\n");
          return -1;
        }

        nwrite = write_buff(tun_fd, sock_buff, sock_len);
        if (nwrite < 0)
        {
          perror("write_buff(tun_fd, buff, len)");
          return -1;
        }

        stored_len = 0;
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
        nwrite = write_u32(client_fd, tun_len);
        if (nwrite < 0)
        {
          perror("write_u32(client_fd, len)");
          return -1;
        }

        nwrite = write_buff(client_fd, tun_buff, tun_len);
        if (nwrite < 0)
        {
          perror("write_buff(client_fd, buff, len)");
          return -1;
        }
      }
    }
  }

  close(client_fd);
  close(tun_fd);
  close(sock_fd);
  close(epfd);
  free(tun_buff);
  free(sock_buff);

	return 0;
}


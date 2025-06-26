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

#ifdef PACKET_PROCESS_TIME
#include <time.h>
#endif

#define MODE SERVER

#define MAX_EVENTS 200
#define BUFFSZ 500*1024

static const char* strstatus(char status)
{
  if (status)
    return "resuming";
  else
    return "started";
}

int main(int argc, char *argv[])
{
  struct config config;
  int tun_fd, sock_fd, client_fd, epfd, nfds, n, nread, nwrite;
  struct epoll_event ev, events[MAX_EVENTS];
  struct sockaddr_in addr;
  socklen_t addr_len;
  char client_ip[16], *tun_buff, *sock_buff;
  uint32_t tun_len, sock_len, stored_len = 0;
  char paused = 0;

#ifdef DEBUG
  unsigned long long sock_id = 0, tun_id = 0;
#endif

#ifdef PACKET_PROCESS_TIME
  clock_t tun_start, tun_finish, sock_start, sock_finish;
#endif

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

    /* Optimization Idea
     * 
     * if socket read is paused:
     *   make sure we handle tun_fd first
     * else:
     *   whatever
     *
     * */
    if (paused && nfds > 1 && events[1].data.fd == tun_fd)
    {
      debug("issue swap events\n");
      ev = events[1];
      events[1] = events[0];
      events[0] = ev;
    }

    for (n = 0; n < nfds; n++)
    {
      if (events[n].data.fd == client_fd)
      {

        if (paused)
          goto begin_read_buff;
#ifdef PACKET_PROCESS_TIME
        else
          sock_start = clock();
#endif

#ifdef DEBUG
        if (sock_id + 1 < sock_id)
          sock_id = 0;

        sock_id++;
#endif

        nread = read_u32(client_fd, &sock_len);
        if (nread < 0)
        {
          printf("read_u32(client_fd, &len)\n");
          return -1;
        }

begin_read_buff:
        debug("[R] %ld: issue read: status: %s, total: %u, got: %u\n", sock_id, strstatus(paused), sock_len, stored_len);
        nread = read_buff(client_fd, sock_buff+stored_len, sock_len-stored_len);
        stored_len += (uint32_t)nread;

        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          debug("[R] %ld: issue pause: status: %s, total: %u, got: %u\n", sock_id, strstatus(paused), sock_len, stored_len);
          paused = 1;
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
#ifdef PACKET_PROCESS_TIME
        sock_finish = clock();
        debug("[R] %ld: finished read operation: status: %s, total: %u, got: %u, took: %f ms\n", sock_id, strstatus(paused), sock_len, stored_len,
            ((double)(sock_finish - sock_start) / CLOCKS_PER_SEC) * 1000);
#else
        debug("[R] %ld: finished read operation: status: %s, total: %u, got: %u\n", sock_id, strstatus(paused), sock_len, stored_len);
#endif

        stored_len = 0;
        paused = 0;
      }
      else if (events[n].data.fd == tun_fd)
      {

#ifdef PACKET_PROCESS_TIME
        tun_start = clock();
#endif

#ifdef DEBUG
        if (tun_id + 1 < tun_id)
          tun_id = 0;

        tun_id++;
#endif

        nread = read_buff2(tun_fd, tun_buff, BUFFSZ);
        if (nread < 0)
        {
          printf("read_buff(tun_fd, buff, BUFFSZ)\n");
          return -1;
        }

        tun_len = (uint32_t)nread;
        debug("[W] %ld: issue write to peer: len: %u\n", tun_id, tun_len);
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
#ifdef PACKET_PROCESS_TIME
        tun_finish = clock();
        debug("[W] %ld: finished write operation: wrote: %d bytes, expected to write %u bytes, took %f ms\n", tun_id, nwrite, tun_len,
            ((double)(tun_finish - tun_start) / CLOCKS_PER_SEC) * 1000);
#else
        debug("[W] %ld: finished write operation: wrote: %d bytes, expected to write %u bytes\n", tun_id, nwrite, tun_len);
#endif
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


#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "wrap.h"

int main(int argc, const char **argv) {
	(void)(argc);
	(void)(argv);

	int fd = 0;

	struct event_base *event;
	struct my_wrap_data *wrap_data;

	int ret = 0;

	struct sockaddr_in addr_remote;
	struct sockaddr_storage addr_local;
	socklen_t addr_local_len = sizeof(addr_local);

	if ((fd = socket(AF_INET, SOCK_DGRAM|SOCK_NONBLOCK, 0)) < 0) {
		printf("Failed to create socket: %s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	if ((event = event_base_new ()) == NULL) {
		printf("Failed to create event base\n");
		ret = 1;
		goto out_close;
	}

	memset(&addr_remote, 0, sizeof(addr_remote));
	memset(&addr_local, 0, sizeof(addr_local));

	addr_remote.sin_family = AF_INET;
	addr_remote.sin_addr.s_addr = inet_addr(SERVER_ADDR);
	addr_remote.sin_port = htons(SERVER_PORT);

	if (getsockname(fd, (struct sockaddr *) &addr_local, &addr_local_len) != 0) {
		printf("Failed to get local address: %s\n", strerror(errno));
		ret = 1;
		goto out_free_event;
	}

	if (my_wrap_data_new (
			&wrap_data,
			SERVER_ADDR,
			(const struct sockaddr *) &addr_remote,
			sizeof(addr_remote),
			(const struct sockaddr *) &addr_local,
			addr_local_len,
			fd,
			event
	)) {
		ret = 1;
		goto out_free_event;
	}

	ret = (event_base_loop(event, 0) != 0
		? 1
		: 0
	) | my_wrap_get_event_ret(wrap_data);

	goto out_destroy_wrap_data;
	out_destroy_wrap_data:
		my_wrap_data_destroy(wrap_data);
	out_free_event:
		event_base_free(event);
	out_close:
		close(fd);
	out:
		return ret;
}

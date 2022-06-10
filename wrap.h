#ifndef MY_WRAP_H
#define MY_WRAP_H

#include <sys/socket.h>

#define QUIC_CIPHERS  \
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256"
#define QUIC_GROUPS   \
    "P-256:X25519:P-384:P-521"
#define H3_ALPN_H3_29 \
    "\x5h3-29"
#define H3_ALPN_H3 \
    "\x2h3"

#define SERVER_ADDR     "127.0.0.1"
#define SERVER_PORT     4433
#define SERVER_ENDPOINT "/README.rst"

//#define SERVER_ADDR "142.250.74.164"
//#define SERVER_PORT 443

struct my_ngtcp2_ctx;
struct my_nghttp3_ctx;
struct my_wrap_data;
struct event_base;

int my_wrap_data_new (
		struct my_wrap_data **result,
		const char *name_remote,
		const struct sockaddr *addr_remote,
		socklen_t addr_remote_len,
		const struct sockaddr *addr_local,
		socklen_t addr_local_len,
		int fd,
		struct event_base *event
);
void my_wrap_data_destroy (
		struct my_wrap_data *wrap_data
);
int my_wrap_get_event_ret (
		struct my_wrap_data *wrap_data
);

#endif /* MY_WRAP_H */

#ifndef MY_NGTCP2_H
#define MY_NGTCP2_H

#include <sys/socket.h>
#include <inttypes.h>

struct event_base;
struct my_ngtcp2_ctx;
typedef struct my_ngtcp2_vec my_ngtcp2_vec;

typedef int (*my_ngtcp2_cb_ready)(void *arg);
typedef int (*my_ngtcp2_cb_get_data)(int64_t *stream_id, my_ngtcp2_vec *vec, size_t *vec_count, int *fin, void *arg);
typedef int (*my_ngtcp2_cb_ack_data)(int64_t stream_id, size_t bytes, void *arg);
typedef int (*my_ngtcp2_cb_deliver_data)(size_t *consumed, int64_t stream_id, const uint8_t *buf, size_t buflen, int fin, void *arg);
typedef int (*my_ngtcp2_cb_block_stream)(int64_t stream_id, int blocked, void *arg);

int my_ngtcp2_ctx_new (
		struct my_ngtcp2_ctx **result,
		const char *name_remote,
		const struct sockaddr *addr_remote,
		const socklen_t addr_remote_len,
		const struct sockaddr *addr_local,
		const socklen_t addr_local_len,
		int fd,
		const char *quic_ciphers,
		const char *quic_groups,
		const char *alpn,
		struct event_base *event,
		my_ngtcp2_cb_ready cb_ready,
		my_ngtcp2_cb_get_data cb_get_data,
		my_ngtcp2_cb_ack_data cb_ack_data,
		my_ngtcp2_cb_deliver_data cb_deliver_data,
		my_ngtcp2_cb_block_stream cb_block_stream,
		void *cb_arg
);
int my_ngtcp2_get_event_ret (
		struct my_ngtcp2_ctx *ctx
);
void my_ngtcp2_ctx_destroy (
		struct my_ngtcp2_ctx *ctx
);
int my_ngtcp2_new_stream (
		int64_t *result,
		struct my_ngtcp2_ctx *ctx
);
int my_ngtcp2_get_ctrl_streams (
		int64_t *result_ctrl,
		int64_t *result_qpack_enc,
		int64_t *result_qpack_dec,
		struct my_ngtcp2_ctx *ctx
);

#endif /* MY_NGTCP2_H */

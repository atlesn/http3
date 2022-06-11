#ifndef MY_NGHTTP3_H
#define MY_NGHTTP3_H

#include <inttypes.h>
#include <stdio.h>
		
typedef struct my_ngtcp2_vec my_ngtcp2_vec;
struct my_nghttp3_ctx;
		
struct my_nghttp3_data {
	const char *data;
	size_t data_bytes;
	size_t data_bytes_written;
};

int my_nghttp3_ctx_new (
		struct my_nghttp3_ctx **result
);
void my_nghttp3_ctx_destroy (
		struct my_nghttp3_ctx *ctx
);
int my_nghttp3_submit_request_with_body (
		struct my_nghttp3_ctx *ctx,
		uint64_t stream_id,
		const char *endpoint,
		const char *host,
		const char *method,
		const char *content_type,
		struct my_nghttp3_data *data
);
int my_nghttp3_submit_request (
		struct my_nghttp3_ctx *ctx,
		uint64_t stream_id,
		const char *endpoint,
		const char *host
);
int my_nghttp3_bind_ctrl_streams (
		struct my_nghttp3_ctx *ctx,
		int64_t ctrl_stream_id,
		int64_t qpack_enc_stream_id,
		int64_t qpack_dec_stream_id
);
int my_nghttp3_report_ack (
		struct my_nghttp3_ctx *ctx,
		int64_t stream_id,
		size_t bytes
);
int my_nghttp3_block_stream (
		struct my_nghttp3_ctx *ctx,
		int64_t stream_id,
		int blocked
);
int my_nghttp3_get_data (
		struct my_nghttp3_ctx *ctx,
		int64_t *stream_id,
		my_ngtcp2_vec *vec,
		size_t *vec_count,
		int *fin
);
int my_nghttp3_deliver_data (
		struct my_nghttp3_ctx *ctx,
		size_t *consumed,
		int64_t stream_id,
		const uint8_t *buf,
		size_t buflen,
		int fin
);

#endif /* MY_NGHTTP3_H */

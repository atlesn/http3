#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "wrap.h"
#include "vec.h"
#include "ngtcp2.h"
#include "nghttp3.h"

struct my_wrap_data {
	struct my_ngtcp2_ctx *ngtcp2_ctx;
	struct my_nghttp3_ctx *nghttp3_ctx;
};

int my_wrap_submit_request (
		int64_t *result,
		struct my_wrap_data *data,
		const char *endpoint,
		const char *host
) {
	int ret = 0;

	*result = 0;

	int64_t stream_id = 0;

	if ((ret = my_ngtcp2_new_stream(&stream_id, data->ngtcp2_ctx)) != 0) {
		goto out;
	}

	if ((ret = my_nghttp3_submit_request(data->nghttp3_ctx, stream_id, endpoint, host)) != 0) {
		goto out;
	}

	*result = stream_id;

	out:
	return ret;
}

int my_wrap_cb_ready (void *arg) {
	struct my_wrap_data *data = arg;

	int64_t ctrl_stream_id = 0;
	int64_t qpack_enc_stream_id = 0;
	int64_t qpack_dec_stream_id = 0;
	int64_t request_stream_id = 0;

	int ret = 0;

	if ((ret = my_ngtcp2_get_ctrl_streams(&ctrl_stream_id, &qpack_enc_stream_id, &qpack_dec_stream_id, data->ngtcp2_ctx)) != 0) {
		goto out;
	}

	if ((ret = my_nghttp3_bind_ctrl_streams(data->nghttp3_ctx, ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id)) != 0) {
		goto out;
	}

	if ((ret = my_wrap_submit_request(&request_stream_id, data, SERVER_ENDPOINT, SERVER_ADDR)) != 0) {
		goto out;
	}

	out:
	return ret;
}

int my_wrap_cb_ack_data (
		int64_t stream_id,
		size_t bytes,
		void *arg
) {
	struct my_wrap_data *data = arg;
	return my_nghttp3_report_ack(data->nghttp3_ctx, stream_id, bytes);
}

int my_wrap_cb_block_stream (
		int64_t stream_id,
		int blocked,
		void *arg
) {
	struct my_wrap_data *data = arg;
	return my_nghttp3_block_stream(data->nghttp3_ctx, stream_id, blocked);
}

int my_wrap_cb_get_data (
		int64_t *stream_id,
		my_ngtcp2_vec *vec,
		size_t *vec_count,
		int *fin,
		void *arg
) {  
	struct my_wrap_data *data = arg;
	return my_nghttp3_get_data(data->nghttp3_ctx, stream_id, vec, vec_count, fin);
}

int my_wrap_cb_deliver_data (
		size_t *consumed,
		int64_t stream_id,
		const uint8_t *buf,
		size_t buflen,
		int fin,
		void *arg
) {
	struct my_wrap_data *data = arg;
	return my_nghttp3_deliver_data(data->nghttp3_ctx, consumed, stream_id, buf, buflen, fin);
}

int my_wrap_data_new (
		struct my_wrap_data **result,
		const char *name_remote,
		const struct sockaddr *addr_remote,
		socklen_t addr_remote_len,
		const struct sockaddr *addr_local,
		socklen_t addr_local_len,
		int fd,
		struct event_base *event
) {
	int ret = 0;

	struct my_wrap_data *wrap_data;

	if ((wrap_data = malloc(sizeof(*wrap_data))) == NULL) {
		printf("Failed to allocate wrap data in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(wrap_data, '\0', sizeof(*wrap_data));

	if (my_ngtcp2_ctx_new (
			&wrap_data->ngtcp2_ctx,
			name_remote,
			addr_remote,
			addr_remote_len,
			addr_local,
			addr_local_len,
			fd,
			QUIC_CIPHERS,
			QUIC_GROUPS,
			H3_ALPN_H3_29 H3_ALPN_H3,
			event,
			my_wrap_cb_ready,
			my_wrap_cb_get_data,
			my_wrap_cb_ack_data,
			my_wrap_cb_deliver_data,
			my_wrap_cb_block_stream,
			wrap_data
	) != 0) {
		goto out_destroy_wrap_data;
	}

	if ((ret = my_nghttp3_ctx_new (
			&wrap_data->nghttp3_ctx
	)) != 0) {
		goto out_destroy_ngtcp2;
	}

	*result = wrap_data;

	goto out;
//	out_destroy_nghttp3:
//		my_nghttp3_ctx_destroy(wrap_data->nghttp3_ctx);
	out_destroy_ngtcp2:
		my_ngtcp2_ctx_destroy(wrap_data->ngtcp2_ctx);
	out_destroy_wrap_data:
		free(wrap_data);
	out:
		return ret;
}

void my_wrap_data_destroy (
		struct my_wrap_data *wrap_data
) {
	my_nghttp3_ctx_destroy(wrap_data->nghttp3_ctx);
	my_ngtcp2_ctx_destroy(wrap_data->ngtcp2_ctx);
	free(wrap_data);
}

int my_wrap_get_event_ret (
		struct my_wrap_data *wrap_data
) {
	return my_ngtcp2_get_event_ret(wrap_data->ngtcp2_ctx);
}

#include <nghttp3/nghttp3.h>
#include <string.h>
#include <stdio.h>

#include "nghttp3.h"
#include "vec.h"

struct my_nghttp3_ctx {
	nghttp3_conn *conn;
};

int my_nghttp3_cb_acked_stream_data (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t datalen,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(datalen);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

int my_nghttp3_cb_stream_close (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(app_error_code);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

int my_nghttp3_cb_recv_data (
		nghttp3_conn *conn,
		int64_t stream_id,
		const uint8_t *data,
		size_t datalen,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(data);
	(void)(datalen);
	(void)(conn_user_data);
	(void)(stream_user_data);

	printf("Data: %.*s\n", (int) datalen, data);

	return 0;
}

int my_nghttp3_cb_deferred_consume (
		nghttp3_conn *conn,
		int64_t stream_id,
		size_t consumed,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(consumed);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

int my_nghttp3_cb_recv_header (
		nghttp3_conn *conn,
		int64_t stream_id,
		int32_t token,
		nghttp3_rcbuf *name,
		nghttp3_rcbuf *value,
		uint8_t flags,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(token);
	(void)(name);
	(void)(value);
	(void)(flags);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

int my_nghttp3_cb_stop_sending (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(app_error_code);
	(void)(conn_user_data);
	(void)(stream_user_data);
	return 0;
}

int my_nghttp3_cb_reset_stream (
		nghttp3_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(app_error_code);
	(void)(conn_user_data);
	(void)(stream_user_data);

	printf("Reset stream %li\n", stream_id);

	return 0;
}

int my_nghttp3_cb_end_stream (
		nghttp3_conn *conn,
		int64_t stream_id,
		void *conn_user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(conn_user_data);
	(void)(stream_user_data);

	printf("End stream %li\n", stream_id);

	return 0;
}

int my_nghttp3_ctx_new (
		struct my_nghttp3_ctx **result
) {
	int ret = 0;

	*result = 0;

	struct my_nghttp3_ctx *ctx;

	if ((ctx = malloc(sizeof(*ctx))) == NULL) {
		printf("Could not allocate memory for ctx in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(ctx, '\0', sizeof(*ctx));

	static nghttp3_callbacks callbacks = {
		my_nghttp3_cb_acked_stream_data,
		my_nghttp3_cb_stream_close,
		my_nghttp3_cb_recv_data,
		my_nghttp3_cb_deferred_consume,
		NULL, /* begin_headers */
		my_nghttp3_cb_recv_header,
		NULL, /* end_headers */
		NULL, /* begin_trailers */
		NULL, /* recv_trailer */
		NULL, /* end_trailers */
		my_nghttp3_cb_stop_sending,
		my_nghttp3_cb_end_stream,
		my_nghttp3_cb_reset_stream,
		NULL, /* shutdown */
	};

	nghttp3_settings settings = {0};
	nghttp3_settings_default(&settings);

	if (nghttp3_conn_client_new (
			&ctx->conn,
			&callbacks,
			&settings,
			nghttp3_mem_default(),
			ctx
	) != 0) {
		printf("Failed to create http3 client\n");
		ret = 1;
		goto out;
	}

	*result = ctx;

	out:
	return ret;
}

void my_nghttp3_ctx_destroy (
		struct my_nghttp3_ctx *ctx
) {
	nghttp3_conn_del(ctx->conn);
	free(ctx);
}

int my_nghttp3_submit_request (
		struct my_nghttp3_ctx *ctx,
		uint64_t stream_id,
		const char *endpoint,
		const char *host
) {
	int ret = 0;
	int ret_tmp;

	nghttp3_nv nv[4] = {0};

	// Note : Cast away const

	nv[0].name = (uint8_t *) ":method";
	nv[0].namelen = strlen(":method");
	nv[0].value = (uint8_t *) "GET";
	nv[0].valuelen = strlen("GET");

	nv[1].name = (uint8_t *) ":scheme";
	nv[1].namelen = strlen(":scheme");
	nv[1].value = (uint8_t *) "https";
	nv[1].valuelen = strlen("https");

	nv[2].name = (uint8_t *) ":path";
	nv[2].namelen = strlen(":path");
	nv[2].value = (uint8_t *) endpoint;
	nv[2].valuelen = strlen(endpoint);

	nv[3].name = (uint8_t *) ":authority";
	nv[3].namelen = strlen(":authority");
	nv[3].value = (uint8_t *) host;
	nv[3].valuelen = strlen(host);

	printf("== Submit request %s %s://%s/%s stream %li\n", nv[0].value, nv[1].value, host, endpoint, stream_id);

	if ((ret_tmp = nghttp3_conn_submit_request (ctx->conn, stream_id, nv, 4, NULL, ctx)) != 0) {
		printf("Failed to submit HTTP3 request: %s\n", nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int my_nghttp3_bind_ctrl_streams (
		struct my_nghttp3_ctx *ctx,
		int64_t ctrl_stream_id,
		int64_t qpack_enc_stream_id,
		int64_t qpack_dec_stream_id
) {
	int ret = 0;
	int ret_tmp;

	if ((ret_tmp = nghttp3_conn_bind_control_stream(ctx->conn, ctrl_stream_id)) != 0) {
		printf("Failed to bind control stream: %s\n", nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	if ((ret_tmp = nghttp3_conn_bind_qpack_streams(ctx->conn, qpack_enc_stream_id, qpack_dec_stream_id)) != 0) {
		printf("Failed to bind qpack streams: %s\n", nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int my_nghttp3_report_ack (
		struct my_nghttp3_ctx *ctx,
		int64_t stream_id,
		size_t bytes
) {
	int ret = 0;
	ssize_t ret_tmp = 0;

	if ((ret_tmp = nghttp3_conn_add_ack_offset (
			ctx->conn,
			stream_id,
			bytes
	)) != 0) {
		printf("Error while ACKing data to HTTP3: %s\n", nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int my_nghttp3_block_stream (
		struct my_nghttp3_ctx *ctx,
		int64_t stream_id,
		int blocked
) {
	int ret = 0;
	ssize_t ret_tmp = 0;

	if ((ret_tmp = (blocked ? nghttp3_conn_block_stream : nghttp3_conn_unblock_stream) (
			ctx->conn,
			stream_id
	)) != 0) {
		printf("Error while blocking/unblocking HTTP3 stream: %s\n", nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	out:
	return ret;
}

int my_nghttp3_get_data (
		struct my_nghttp3_ctx *ctx,
		int64_t *stream_id,
		my_ngtcp2_vec *vec,
		size_t *vec_count,
		int *fin
) {
	int ret = 0;
	ssize_t ret_tmp = 0;

	if ((ret_tmp = nghttp3_conn_writev_stream (
			ctx->conn,
			stream_id,
			fin,
			(nghttp3_vec *) vec,
			*vec_count
	)) < 0) {
		printf("Failed to get http3 data %s\n", nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	*vec_count = (size_t) ret_tmp;

	out:
	return ret;
}

int my_nghttp3_deliver_data (
		struct my_nghttp3_ctx *ctx,
		size_t *consumed,
		int64_t stream_id,
		const uint8_t *buf,
		size_t buflen,
		int fin
) {
	int ret = 0;
	ssize_t ret_tmp = 0;

	*consumed = 0;

	if ((ret_tmp = nghttp3_conn_read_stream (
			ctx->conn,
			stream_id,
			buf,
			buflen,
			fin
	)) < 0) {
		printf("Failed to deliver http3 data %s\n", nghttp3_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	*consumed = (size_t) ret_tmp;

	out:
	return ret;
}

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_openssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "ngtcp2.h"

#define KEEP_ALIVE_S 10
#define PONG_TIMEOUT_S (KEEP_ALIVE_S * 2)
#define HANDSHAKE_TIMEOUT_S 1

struct my_ngtcp2_ctx {
	ngtcp2_conn *conn;
	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_path path;
	ngtcp2_settings settings;
	ngtcp2_transport_params transport_params;
	ngtcp2_connection_close_error last_error;
	struct sockaddr_storage addr_remote;
	socklen_t addr_remote_len;
	struct sockaddr_storage addr_local;
	socklen_t addr_local_len;
	SSL_CTX *sslctx;
	SSL *ssl;
	uint8_t tls_alert;
	struct event_base *event;
	struct event *event_read;
	struct event *event_write;
	struct event *event_timeout;
	int event_ret;
	int handshake_complete;
	my_ngtcp2_cb_ready cb_ready;
	my_ngtcp2_cb_get_data cb_get_data;
	my_ngtcp2_cb_ack_data cb_ack_data;
	my_ngtcp2_cb_deliver_data cb_deliver_data;
	my_ngtcp2_cb_block_stream cb_block_stream;
	void *cb_arg;
};

int my_timestamp_nano(uint64_t *result) {
	struct timespec tp;

	*result = 0;

	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
		printf("Failed to get time in %s: %s\n", __func__, strerror(errno));
		return 1;
	}

	*result = (uint64_t) tp.tv_sec * NGTCP2_SECONDS + (uint64_t) tp.tv_nsec;

	return 0;
}

void my_random(void *target, size_t bytes) {
	static int first = 1;

	if (first) {
		srand((unsigned int) time(NULL));
		first = 0;
	}

	unsigned char *dataptr = target;

	for (size_t i = 0; i < bytes; i++) {
		*dataptr = (unsigned char) rand();
		dataptr++;
	}
}

int my_ngtcp2_cb_handshake_complete (ngtcp2_conn *conn, void *user_data) {
	(void)(user_data);

	printf("Handshake complete\n");

	ngtcp2_conn_set_keep_alive_timeout(conn, (ngtcp2_duration) KEEP_ALIVE_S * 1000 * 1000 * 1000);

	return 0;
}

int my_ngtcp2_cb_receive_stream_data (
		ngtcp2_conn *conn,
		uint32_t flags,
		int64_t stream_id,
		uint64_t offset,
		const uint8_t *buf,
		size_t buflen,
		void *user_data,
		void *stream_user_data
) {
	struct my_ngtcp2_ctx *ctx = user_data;

	(void)(offset);
	(void)(stream_user_data);

	size_t consumed = 0;

	printf("Receive: %llu - %s fin %i\n", (unsigned long long) buflen, buf, flags & NGTCP2_STREAM_DATA_FLAG_FIN);

	if (ctx->cb_deliver_data (
			&consumed,
			stream_id,
			buf,
			buflen,
			(flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0,
			ctx->cb_arg
	) != 0) {
		return 1;
	}

	// NGTCP2_ERR_CALLBACK_FAILURE / ngtcp2_conection_close_error_set_application_error

	ngtcp2_conn_extend_max_stream_offset(conn, stream_id, consumed);
	ngtcp2_conn_extend_max_offset(conn, consumed);

	return 0;
}

int my_ngtcp2_cb_acked_stream_data_offset (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t offset,
		uint64_t datalen,
		void *user_data,
		void *stream_user_data
) {
	struct my_ngtcp2_ctx *ctx = user_data;

	(void)(ctx);
	(void)(conn);
	(void)(offset);
	(void)(stream_user_data);

	printf("ACK from remote Stream %lli, %llu bytes \n", (long long int) stream_id, (unsigned long long) datalen);

	// nghttp3_conn_add_ack_offset(m stream_id, datalen);
	// NGTCP2_ERR_CALLBACK_FAILURE / ngtcp2_conection_close_error_set_application_error
	return 0;
}
		
int my_ngtcp2_cb_stream_close (
		ngtcp2_conn *conn,
		uint32_t flags,
		int64_t stream_id,
		uint64_t app_error_code,
		void *user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(app_error_code);
	(void)(user_data);
	(void)(stream_user_data);

	if (!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
		// app_error_close = NGHTTP3_H3_NO_ERROR;
	}

	printf("Close stream %li\n", stream_id);

	return 0;
}
		
int my_ngtcp2_cb_extend_max_local_streams_bidi (
		ngtcp2_conn *conn,
		uint64_t max_streams,
		void *user_data
) {
	struct my_ngtcp2_ctx *ctx = user_data;

	(void)(conn);

	printf("Extend max streams: %llu\n", (unsigned long long) max_streams);

	if (ctx->cb_ready != NULL && ctx->cb_ready(ctx->cb_arg) != 0) {
		return 1;
	}

	// Call only once
	ctx->cb_ready = NULL;

	return 0;
}

void my_ngtcp2_cb_random (
		uint8_t *dest,
		size_t destlen,
		const ngtcp2_rand_ctx *rand_ctx
) {
	(void)(rand_ctx);
	my_random(dest, destlen);
}

int my_ngtcp2_cb_get_new_connection_id (
		ngtcp2_conn *conn,
		ngtcp2_cid *cid,
		uint8_t *token,
		size_t cidlen,
		void *user_data
) {
	(void)(conn);
	(void)(user_data);

	cid->datalen = cidlen;
	my_random(&cid->data, cidlen);
	my_random(token, NGTCP2_STATELESS_RESET_TOKENLEN);

	return 0;
}
		
int my_ngtcp2_cb_stream_reset (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t final_size,
		uint64_t app_error_code,
		void *user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(final_size);
	(void)(app_error_code);
	(void)(user_data);
	(void)(stream_user_data);

	printf("Stream reset\n");

	// NGTCP2_ERR_CALLBACK_FAILURE - nghttp3_conn_shutdown_stream_read
	
	return 0;
}

int my_ngtcp2_cb_extend_max_stream_data (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t max_data,
		void *user_data,
		void *stream_user_data
) {
	struct my_ngtcp2_ctx *ctx = user_data;

	(void)(conn);
	(void)(max_data);
	(void)(stream_user_data);

	printf("Extend max stream data stream %lli\n", (long long int) stream_id);

	if (ctx->cb_ready != NULL && ctx->cb_block_stream(stream_id, 0 /* Unblock */, ctx->cb_arg) != 0) {
		return 1;
	}

	return 0;
}

int my_ngtcp2_cb_stream_stop_sending (
		ngtcp2_conn *conn,
		int64_t stream_id,
		uint64_t app_error_code,
		void *user_data,
		void *stream_user_data
) {
	(void)(conn);
	(void)(stream_id);
	(void)(app_error_code);
	(void)(user_data);
	(void)(stream_user_data);

	printf("Stop sending\n");

	// NGTCP2_ERR_CALLBACK_FAILURE - nghttp3_conn_shutdown_stream_read

	return 0;
}

int my_ngtcp2_cb_initial (
		ngtcp2_conn *conn,
		void *user_data
) {
	printf("Initial\n");
	return ngtcp2_crypto_client_initial_cb(conn, user_data);
}

int my_ngtcp2_get_message (
		struct my_ngtcp2_ctx *ctx,
		int64_t *stream_id,
		ngtcp2_vec *data_vector,
		size_t *data_vector_count,
		int *fin
) {
	int ret = 0;

	if ((ctx->cb_get_data (
			stream_id,
			(my_ngtcp2_vec *) data_vector,
			data_vector_count,
			fin,
			ctx->cb_arg
	)) != 0) {
		goto out;
	}

	out:
		return ret;
}

int my_ngtcp2_send_packet (
		evutil_socket_t fd,
		const struct sockaddr *addr,
		socklen_t addr_len,
		const uint8_t *data,
		size_t data_size
) {
	ssize_t bytes_written = 0;

	printf("Sending %llu bytes\n", (unsigned long long) data_size);

	do {
		bytes_written = sendto(fd, data, data_size, 0, addr, addr_len);
	} while (bytes_written < 0 && errno == EINTR);

	if (bytes_written < 0) {
		printf("Error while sending: %s\n", strerror(errno));
		return 1;
	}

	if ((size_t) bytes_written < data_size) {
		printf("All bytes not written in %s\n", __func__);
		return 1;
	}

	return 0;
}

void event_read (evutil_socket_t fd, short e, void *a) {
	struct my_ngtcp2_ctx *ctx = a;

	(void)(e);

	char buf[65536];
	ssize_t bytes = 0;
	struct sockaddr_storage remote_addr = {0};
	socklen_t remote_addr_len = sizeof(remote_addr);
	ngtcp2_path path = ctx->path;
	ngtcp2_pkt_info packet_info = {0};
	uint64_t timestamp = 0;
	int ret_tmp = 0;
	int loops = 0;

	printf("Read event\n");

	for (;;) {
		if (my_timestamp_nano(&timestamp) != 0) {
			goto out_failure;
		}

		bytes = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &remote_addr, &remote_addr_len);

		if (bytes == 0) {
			printf("read EOF\n");
			goto out_eof;
		}
		else if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			printf("read EAGAIN\n");
			break;
		}
		else if (bytes < 0) {
			printf("Error while reading: %s\n", strerror(errno));
			goto out_failure;
		}

		printf("Read %lli bytes\n", (long long) bytes);

		loops++;

		path.remote.addr = (ngtcp2_sockaddr *) &remote_addr;
		path.remote.addrlen = remote_addr_len;

		if ((ret_tmp = ngtcp2_conn_read_pkt (
				ctx->conn,
				&path,
				&packet_info,
				(const uint8_t *) buf,
				(size_t) bytes,
				timestamp
		)) != 0) {
			if (ret_tmp == NGTCP2_ERR_DRAINING) {
				printf("Connection was closed (now in draining state) while reading\n");
				goto out_eof;
			}
			else if (ret_tmp == NGTCP2_ERR_CRYPTO) {
				printf("Crypto error while reading packet: %s\n", ngtcp2_strerror(ret_tmp));
				ngtcp2_connection_close_error_set_transport_error_tls_alert (
						&ctx->last_error,
						ngtcp2_conn_get_tls_alert(ctx->conn),
						NULL,
						0
				);
			}
			else {
				printf("Transport error while reading packet: %s\n", ngtcp2_strerror(ret_tmp));
				ngtcp2_connection_close_error_set_transport_error_liberr (
						&ctx->last_error,
						ret_tmp,
						NULL,
						0
				);
			}
			goto out_failure;
		}
	}

	if (!event_pending(ctx->event_write, EV_WRITE, NULL)) {
		event_add(ctx->event_write, NULL);
	}

	if (loops > 0) {
		const struct timeval timeout = {PONG_TIMEOUT_S, 0};
		event_add(ctx->event_timeout, &timeout);
	}

	return;
	out_eof:
		ctx->event_ret = 0;
		goto out;
	out_failure:
		ctx->event_ret = 1;
		goto out;
	out:
		event_base_loopbreak(ctx->event);

}

void event_timeout (evutil_socket_t fd, short e, void *a) {
	struct my_ngtcp2_ctx *ctx = a;

	(void)(fd);
	(void)(e);

	printf("Read timeout\n");

	ctx->event_ret = 1;
	event_base_loopbreak(ctx->event);
}

uint64_t vec_len(const ngtcp2_vec *vec, size_t n) {
	size_t i;
	size_t res = 0;

	for (i = 0; i < n; ++i) {
		res += vec[i].len;
	}

	return res;
}

void event_write (evutil_socket_t fd, short e, void *a) {
	struct my_ngtcp2_ctx *ctx = a;

	(void)(e);

	char buf[1280];
	ngtcp2_vec data_vector[128] = {0};
	size_t data_vector_count = 0;
	ngtcp2_path_storage path_storage;
	ngtcp2_pkt_info packet_info = {0};
	int fin = 0;
	ngtcp2_ssize bytes_from_src = 0;
	ngtcp2_ssize bytes_to_buf = 0;
	uint64_t timestamp = 0;
	int64_t stream_id = -1;

	ngtcp2_path_storage_zero(&path_storage);

	printf("Write event\n");

	for (;;) {
		if (my_timestamp_nano(&timestamp) != 0) {
			goto out_failure;
		}

		printf("++ Loop\n");

		data_vector_count = sizeof(data_vector)/sizeof(*data_vector);
		if (my_ngtcp2_get_message (
					ctx,
					&stream_id,
					data_vector,
					&data_vector_count,
					&fin
		) != 0) {
			goto out_failure;
		}

		printf("Vector count %llu len %llu stream ID %lli fin %i\n",
				(unsigned long long) data_vector_count,
				(unsigned long long) vec_len(data_vector, data_vector_count),
				(long long int) stream_id,
				fin
		);

		if (!fin && stream_id == -1 && data_vector_count == 0) {
			printf("- No data from http3\n");
		}

		bytes_to_buf = ngtcp2_conn_writev_stream (
				ctx->conn,
				&path_storage.path,
				&packet_info,
				(uint8_t *) buf,
				sizeof(buf),
				&bytes_from_src,
				NGTCP2_WRITE_STREAM_FLAG_MORE | (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0),
				stream_id,
				data_vector,
				data_vector_count,
				timestamp
		);

		printf("- Write out: %li, Write in: %li\n", bytes_to_buf, bytes_from_src);

		if (bytes_to_buf < 0) {
			if (bytes_to_buf == NGTCP2_ERR_STREAM_DATA_BLOCKED || bytes_to_buf == NGTCP2_ERR_STREAM_SHUT_WR) {
				printf("- Blocked\n");
				if (ctx->cb_block_stream(stream_id, 1 /* Blocked*/, ctx->cb_arg) != 0) {
					//		ngtcp2_connection_close_error_set_application_error();
					goto out_failure;
				}
			}
			else if (bytes_to_buf == NGTCP2_ERR_WRITE_MORE) {
				// Must call writev repeatedly until complete.
				assert(bytes_from_src >= 0);
				printf("- More\n");

				if (ctx->cb_ack_data(stream_id, bytes_from_src, ctx->cb_arg) != 0) {
					//		ngtcp2_connection_close_error_set_application_error();
					goto out_failure;
				}
			}
			else {
				printf("Error while writing: %s\n", ngtcp2_strerror((int) bytes_to_buf));
				goto out_failure;
			}
		}
		else if (bytes_to_buf == 0) {
			break;
		}

		if (bytes_to_buf > 0 && my_ngtcp2_send_packet (
					fd,
					(const struct sockaddr *) path_storage.path.remote.addr,
					path_storage.path.remote.addrlen,
					(const uint8_t *) buf,
					bytes_to_buf
		) != 0) {
			goto out_failure;
		}
	}

	event_del(ctx->event_write);

	return;
	out_failure:
		ctx->event_ret = 1;
		event_base_loopbreak(ctx->event);
		return;
}

static ngtcp2_conn *my_ngtcp2_get_conn (
		ngtcp2_crypto_conn_ref *ngtcp2_ref
) {
	struct my_ngtcp2_ctx *ctx = ngtcp2_ref->user_data;
	return ctx->conn;
}

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
) {
	int ret = 0;

	struct my_ngtcp2_ctx *ctx;

	*result = NULL;

	if ((ctx = malloc(sizeof(*ctx))) == NULL) {
		printf("Failed to allocate ctx in %s\n", __func__);
		ret = 1;
		goto out;
	}

	memset(ctx, 0, sizeof(*ctx));

	ctx->conn_ref.get_conn = my_ngtcp2_get_conn;
	ctx->conn_ref.user_data = ctx;

	ctx->cb_ready = cb_ready;
	ctx->cb_get_data = cb_get_data;
	ctx->cb_ack_data = cb_ack_data;
	ctx->cb_deliver_data = cb_deliver_data;
	ctx->cb_block_stream = cb_block_stream;
	ctx->cb_arg = cb_arg;

	ctx->event = event;

	assert(sizeof(ctx->addr_remote) >= addr_remote_len);
	assert(sizeof(ctx->addr_local) >= addr_local_len);

	memcpy(&ctx->addr_remote, addr_remote, addr_remote_len);
	memcpy(&ctx->addr_local, addr_local, addr_local_len);

	ctx->addr_remote_len = addr_remote_len;
	ctx->addr_local_len = addr_local_len;

	if ((ctx->sslctx = SSL_CTX_new(TLS_client_method())) == NULL) {
		printf("Failed to create SSL ctx\n");
		ret = 1;
		goto out_destroy_ctx;
	}

	if (ngtcp2_crypto_openssl_configure_client_context(ctx->sslctx) != 0) {
		printf("Failed to set client SSL ctx\n");
		ret = 1;
		goto out_destroy_ssl_ctx;
	}

	if ((ctx->ssl = SSL_new(ctx->sslctx)) == NULL) {
		printf("Failed to create SSL\n");
		ret = 1;
		goto out_destroy_ssl_ctx;
	}

	SSL_CTX_set_default_verify_paths(ctx->sslctx);

	if (SSL_CTX_set_ciphersuites(ctx->sslctx, quic_ciphers) != 1) {
		printf("Failed to set SSL ciphersuites\n");
		ret = 1;
		goto out_destroy_ssl;
	}

	if (SSL_CTX_set1_groups_list(ctx->sslctx, quic_groups) != 1) {
		printf("Failed to set SSL groups\n");
		ret = 1;
		goto out_destroy_ssl;
	}

	SSL_CTX_set_verify(ctx->sslctx, SSL_VERIFY_PEER, NULL);

	if (!SSL_CTX_load_verify_locations(ctx->sslctx, NULL, "/home/atle/rrr/misc/ssl")) {
		printf("Failed to set verify location\n");
		ret = 1;
		goto out_destroy_ssl;
	}

	SSL_set_app_data(ctx->ssl, &ctx->conn_ref);
	SSL_set_connect_state(ctx->ssl);
	SSL_set_quic_use_legacy_codepoint(ctx->ssl, 0);

	SSL_set_alpn_protos(ctx->ssl, (const uint8_t *) alpn, (int) strlen(alpn));
	SSL_set_tlsext_host_name(ctx->ssl, name_remote);
	SSL_set_quic_transport_version(ctx->ssl, TLSEXT_TYPE_quic_transport_parameters);

	ngtcp2_cid dcid = {.datalen = NGTCP2_MAX_CIDLEN};
	ngtcp2_cid scid = {.datalen = NGTCP2_MAX_CIDLEN};

	assert(sizeof(dcid.data) >= NGTCP2_MAX_CIDLEN);

	ngtcp2_settings_default(&ctx->settings);
	ngtcp2_transport_params_default(&ctx->transport_params);

	my_random(&dcid.data, dcid.datalen);
	my_random(&scid.data, scid.datalen);

	if (my_timestamp_nano(&ctx->settings.initial_ts) != 0) {
		goto out_destroy_ssl;
	}

	ctx->transport_params.initial_max_streams_uni = 3;
	ctx->transport_params.initial_max_stream_data_bidi_local = 128 * 1024;
	ctx->transport_params.initial_max_data = 1024 * 1024;

	static ngtcp2_callbacks callbacks = {
		my_ngtcp2_cb_initial,
		NULL, /* recv_client_initial */
		ngtcp2_crypto_recv_crypto_data_cb,
		my_ngtcp2_cb_handshake_complete,
		NULL, /* recv_version_negotiation */
		ngtcp2_crypto_encrypt_cb,
		ngtcp2_crypto_decrypt_cb,
		ngtcp2_crypto_hp_mask_cb,
		my_ngtcp2_cb_receive_stream_data,
		my_ngtcp2_cb_acked_stream_data_offset,
		NULL, /* stream_open */
		my_ngtcp2_cb_stream_close,
		NULL, /* recv_stateless_reset */
		ngtcp2_crypto_recv_retry_cb,
		my_ngtcp2_cb_extend_max_local_streams_bidi,
		NULL, /* extend_max_local_streams_uni */
		my_ngtcp2_cb_random,
		my_ngtcp2_cb_get_new_connection_id,
		NULL, /* remove_connection_id */
		ngtcp2_crypto_update_key_cb,
		NULL, /* path_validation */
		NULL, /* select_preferred_addr */
		my_ngtcp2_cb_stream_reset,
		NULL, /* extend_max_remote_streams_bidi */
		NULL, /* extend_max_remote_streams_uni */
		my_ngtcp2_cb_extend_max_stream_data,
		NULL, /* dcid_status */
		NULL, /* handshake_confirmed */
		NULL, /* recv_new_token */
		ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		NULL, /* recv_datagram */
		NULL, /* ack_datagram */
		NULL, /* lost_datagram */
		ngtcp2_crypto_get_path_challenge_data_cb,
		my_ngtcp2_cb_stream_stop_sending,
		ngtcp2_crypto_version_negotiation_cb,
		NULL, /* recv_rx_key */
		NULL  /* recv_tx_key */
	};

	ngtcp2_addr_init(&ctx->path.remote, addr_remote, addr_remote_len);
	ngtcp2_addr_init(&ctx->path.local, addr_local, addr_local_len);

	if (ngtcp2_conn_client_new (
			&ctx->conn,
			&dcid,
			&scid,
			&ctx->path,
			NGTCP2_PROTO_VER_V1,
			&callbacks,
			&ctx->settings,
			&ctx->transport_params,
			NULL,
			ctx
	) != 0) {
		printf("Failed to create client\n");
		ret = 1;
		goto out_destroy_ssl;
	}

	ngtcp2_conn_set_tls_native_handle(ctx->conn, ctx->ssl);
	ngtcp2_connection_close_error_default(&ctx->last_error);

	if ((ctx->event_read = event_new (event, fd, EV_READ|EV_PERSIST, event_read, ctx)) == NULL) {
		printf("Failed to create read event\n");
		ret = 1;
		goto out_del_ngtcp2;
	}

	if ((ctx->event_write = event_new (event, fd, EV_WRITE|EV_PERSIST, event_write, ctx)) == NULL) {
		printf("Failed to create write event\n");
		ret = 1;
		goto out_free_event_read;
	}

	if ((ctx->event_timeout = event_new (event, fd, EV_TIMEOUT|EV_PERSIST, event_timeout, ctx)) == NULL) {
		printf("Failed to create timeout event\n");
		ret = 1;
		goto out_free_event_write;
	}

	const struct timeval timeout_read = {0, 500000};
	const struct timeval timeout_handshake = {HANDSHAKE_TIMEOUT_S, 0};

	event_add(ctx->event_read, &timeout_read);
	event_add(ctx->event_timeout, &timeout_handshake);

	// Start with sending the handshake
	event_active(ctx->event_write, 0, 0);

	*result = ctx;
	
	goto out;
//	out_free_event_timeout:
//		event_free(ctx->event_timeout);
	out_free_event_write:
		event_free(ctx->event_write);
	out_free_event_read:
		event_free(ctx->event_read);
	out_del_ngtcp2:
		ngtcp2_conn_del(ctx->conn);
	out_destroy_ssl:
		SSL_free(ctx->ssl);
	out_destroy_ssl_ctx:
		SSL_CTX_free(ctx->sslctx);
	out_destroy_ctx:
		free(ctx);
	out:
		return ret;
}

int my_ngtcp2_get_event_ret (
		struct my_ngtcp2_ctx *ctx
) {
	return ctx->event_ret;
}

void my_ngtcp2_ctx_destroy (
		struct my_ngtcp2_ctx *ctx
) {
	ngtcp2_conn_del(ctx->conn);
	SSL_free(ctx->ssl);
	SSL_CTX_free(ctx->sslctx);
	event_free(ctx->event_read);
	event_free(ctx->event_write);
	event_free(ctx->event_timeout);
	free(ctx);
}

int my_ngtcp2_new_stream (
		int64_t *result,
		struct my_ngtcp2_ctx *ctx
) {
	int ret = 0;
	int ret_tmp;

	*result = 0;

	int64_t stream_id;
	if ((ret_tmp = ngtcp2_conn_open_bidi_stream(ctx->conn, &stream_id, NULL)) != 0) {
		printf("Could not open bidi stream: %s\n", ngtcp2_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	*result = stream_id;

	out:
	return ret;
}

int my_ngtcp2_get_ctrl_streams (
		int64_t *result_ctrl,
		int64_t *result_qpack_enc,
		int64_t *result_qpack_dec,
		struct my_ngtcp2_ctx *ctx
) {
	int ret = 0;
	int ret_tmp;

	*result_ctrl = 0;
	*result_qpack_enc = 0;
	*result_qpack_dec = 0;

	int64_t ctrl_stream_id = 0;
	int64_t qpack_enc_stream_id = 0;
	int64_t qpack_dec_stream_id = 0;

	if ((ret_tmp = ngtcp2_conn_open_uni_stream(ctx->conn, &ctrl_stream_id, NULL)) != 0) {
		printf("Failed to create control stream: %s\n", ngtcp2_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	if ((ret_tmp = ngtcp2_conn_open_uni_stream(ctx->conn, &qpack_enc_stream_id, NULL)) != 0) {
		printf("Failed to create qpack encode stream: %s\n", ngtcp2_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	if ((ret_tmp = ngtcp2_conn_open_uni_stream(ctx->conn, &qpack_dec_stream_id, NULL)) != 0) {
		printf("Failed to create qpack decode stream: %s\n", ngtcp2_strerror(ret_tmp));
		ret = 1;
		goto out;
	}

	*result_ctrl = ctrl_stream_id;
	*result_qpack_enc = qpack_enc_stream_id;
	*result_qpack_dec = qpack_dec_stream_id;

	out:
	return ret;
}

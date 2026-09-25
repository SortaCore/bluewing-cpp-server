/* vim: set noet ts=4 sw=4 sts=4 ft=c:
 *
 * Copyright (C) 2011, 2012 James McLaughlin et al.
 * Copyright (C) 2012-2026 Darkwire Software.
 * All rights reserved.
 *
 * liblacewing and Lacewing Relay/Blue source code are available under MIT license.
 * https://opensource.org/license/mit
*/

#include "common.h"

void lw_server_client_set_websocket (lw_server_client, lw_bool);

static void on_connect (lw_server server, lw_server_client client_socket)
{
	lw_ws ws = (lw_ws) lw_server_tag (server);
	lw_bool secure = (server == ws->socket_secure);

	lwp_ws_client client = lwp_ws_httpclient_new (ws, client_socket, secure);
	if (!client)
	{
	  lw_stream_close ((lw_stream) client_socket, lw_true);
	  return;
	}

	lw_stream_set_tag ((lw_stream) client_socket, client);

	lw_stream_write_stream
	  ((lw_stream) client, (lw_stream) client_socket, SIZE_MAX, lw_false);
}

static void on_disconnect (lw_server server, lw_server_client client_socket)
{
	lwp_ws_client client = (lwp_ws_client) lw_stream_tag ((lw_stream) client_socket);

	// If client is kicked more than once, somehow
	// TODO: Seems to happen for websocket connections under some circumstances
	if (client == NULL)
	{
		long fd = lw_fdstream_get_fd_debug((lw_fdstream)client_socket);
		always_log("client tag is unexpected null for stream %p, fd %ld.", (void *)client_socket, fd);
		return; // no op
	}
	assert (client);

	client->cleanup (client);
	lw_stream_delete ((lw_stream) client);

	lw_stream_set_tag ((lw_stream) client_socket, 0);
}

static void on_error (lw_server server, lw_error error)
{
	lw_error_addf (error, "Socket error");

	lw_ws ws = (lw_ws) lw_server_tag (server);

	if (ws->on_error)
		ws->on_error (ws, error);
}

static size_t websocket_sink_data (lw_stream stream, const char * buffer, size_t size);

static const lw_streamdef def_websocketclient =
{
	websocket_sink_data,
	0, /* sink_stream */
	0, /* retry */
	0, /* is_transparent */
	0, /* close */
	0, /* bytes_left */
	0, /* read */
	0  /* cleanup */
};

static void websocket_tick (lwp_ws_client client)
{
	/* WebSocket connections deliberately have no HTTP idle timeout. */
}

static void websocket_cleanup (lwp_ws_client client)
{
	lw_ws_websocket websocket = (lw_ws_websocket) client;

	if (client->ws->on_websocket_disconnect)
		client->ws->on_websocket_disconnect (client->ws, websocket);
}

lw_ws_websocket lwp_ws_websocket_new (lw_ws ws, lw_server_client socket,
	lw_bool secure)
{
	lw_ws_websocket ctx = (lw_ws_websocket) calloc (sizeof (*ctx), 1);
	if (!ctx)
		return 0;

	ctx->client.ws = ws;
	ctx->client.socket = socket;
	ctx->client.secure = secure;
	ctx->client.tick = websocket_tick;
	ctx->client.cleanup = websocket_cleanup;
	ctx->local_close_code = ctx->remote_close_code = -1;

	lwp_stream_init ((lw_stream) ctx, &def_websocketclient, ws->pump);
	return ctx;
}

void lwp_ws_websocket_disconnect (lw_ws_websocket ctx,
	unsigned int websocket_exit_reason)
{
	if (ctx->local_close_code == -1)
	{
		if (websocket_exit_reason == 0)
			websocket_exit_reason = 1000;

		ctx->local_close_code = (lw_i16) websocket_exit_reason;

		lw_ui16 exit_reason = htons ((lw_ui16) websocket_exit_reason);
		char close_msg [] = { (char) 0b10001000, (char) sizeof (exit_reason),
			((char *) &exit_reason) [0], ((char *) &exit_reason) [1] };
		lwp_stream_write ((lw_stream) ctx->client.socket, close_msg,
			sizeof (close_msg), 0);
	}

	if (ctx->remote_close_code != -1)
		lw_stream_close ((lw_stream) ctx->client.socket, lw_true);
}

lw_addr lw_ws_websocket_addr (lw_ws_websocket ctx)
{
	return lw_server_client_remote_addr (ctx->client.socket);
}

lw_bool lw_ws_websocket_secure (lw_ws_websocket ctx)
{
	return ctx->client.secure;
}

void lw_ws_websocket_disconnect (lw_ws_websocket ctx,
	unsigned int websocket_reason_code)
{
	lwp_ws_websocket_disconnect (ctx, websocket_reason_code);
}

static lw_bool websocket_key_valid (const char * key)
{
	if (strlen (key) != 24 || key [22] != '=' || key [23] != '=')
		return lw_false;

	for (size_t i = 0; i < 22; ++ i)
		if (!isalnum ((unsigned char) key [i]) && key [i] != '+' && key [i] != '/')
			return lw_false;

	return lw_true;
}

static void websocket_accept_value (const char * key, char output [29])
{
	static const char alphabet [] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	char input [61];
	char sha1 [20];
	memcpy (input, key, 24);
	memcpy (input + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
	lw_sha1 (sha1, input, 60);

	for (size_t i = 0, j = 0; i < sizeof (sha1); i += 3)
	{
		unsigned int n = (unsigned char) sha1 [i] << 16;
		if (i + 1 < sizeof (sha1)) n |= (unsigned char) sha1 [i + 1] << 8;
		if (i + 2 < sizeof (sha1)) n |= (unsigned char) sha1 [i + 2];
		output [j ++] = alphabet [n >> 18];
		output [j ++] = alphabet [(n >> 12) & 63];
		output [j ++] = i + 1 < sizeof (sha1) ? alphabet [(n >> 6) & 63] : '=';
		output [j ++] = i + 2 < sizeof (sha1) ? alphabet [n & 63] : '=';
	}
	output [28] = 0;
}

lw_bool lwp_ws_try_websocket_upgrade (lwp_ws_httpclient ctx)
{
	lw_ws ws = ctx->client.ws;
	lw_ws_req req = ctx->request;
	if (!ws->on_websocket_message || !ctx->parser.upgrade)
		return lw_false;

	const char * key = lw_ws_req_header (req, "sec-websocket-key");
	if (strcmp (req->method, "GET") || strcasecmp (lw_ws_req_header (req, "upgrade"), "websocket")
		|| strcmp (lw_ws_req_header (req, "sec-websocket-version"), "13") || !websocket_key_valid (key)
		|| (ws->on_websocket_accept && !ws->on_websocket_accept (ws, req)))
	{
		lw_ws_req_status (req, 400, "Bad WebSocket Request");
		lwp_ws_req_respond (req);
		return lw_true;
	}

	char accept [29];
	websocket_accept_value (key, accept);
	lw_server_client_set_websocket (ctx->client.socket, lw_true);
	lw_ws_req_accept_websocket (req);
	lw_ws_req_set_header (req, "Upgrade", "websocket");
	lw_ws_req_set_header (req, "Connection", "Upgrade");
	lw_ws_req_set_header (req, "Sec-WebSocket-Accept", accept);
	lw_ws_req_status (req, 101, "Switching Protocols");
	lwp_ws_req_respond (req);
	return lw_true;
}

_Bool lw_u8str_validate(const char* toValidate, size_t size);

static size_t websocket_sink_data (lw_stream stream, const char * data, size_t size)
{
	lw_ws_websocket client = (lw_ws_websocket) stream;
	lw_ws webserver = client->client.ws;
	const size_t originalSize = size;
	char * unmaskedData = NULL;
	const char * error = NULL;
	static char error2[256];
	lw_ui32 errorCode = 0;
#define data_remove_prefix(i) data += i; size -= i;

	// use a do loop so we can break out for errors
	do {
		// Minimum packet size - fin/opcode byte, mask + content len byte, 4-byte mask key
		if (size < 1 + 1 + 4)
		{
			error = "message too small to be valid";
			errorCode = 1002; // 1002 = protocol error
			break;
		}

		// The three reserved bits must be 0
		if (data[0] & 0b01110000)
		{
			error = "reserved bits are set";
			errorCode = 1002;
			break;
		}
		// We expect all data in one packet, no continuation
		if (data[0] & 0b1000000)
		{
			error = "fin flag is not set; continuation not allowed";
			errorCode = 1009;
			break;
		}

		lw_ui8 opcode = data[0] & 0b00001111;
		// opcode 0 = continuation of previous packet
		// opcode 1 = text, 2 = binary, 3-7 reserved, 8 connection close, 9 ping, 10 pong, 11-15 reserved
		// We only use 2 and 8, and allow 9-10
		if ((opcode >= 3 && opcode <= 7) || (opcode >= 11 && opcode <= 15))
		{
			error = "reserved opcodes used";
			errorCode = 1002;
			break;
		}
		// Continuation or text are not expected. Continuation is possible, but it'll necessitate adding a cache,
		// so until I see it being used (perhaps under high load), I will stick to small packets.
		// Text isn't used by Bluewing JS, as text messages could only be for "sent TCP to server" messages...
		// so might as well put them in the regular Blue binary format like all the other text message types.
		if (opcode == 0 || opcode == 1)
		{
			sprintf(error2, "opcode %hhu is valid, but not expected by Bluewing", opcode);
			error = error2;
			errorCode = 1003; // 1003 = opcode is OK but not meant to process it
			break;
		}

		// WebSocket spec demands XOR masking from client->server, and requires no mask server -> client
		if ((data[1] & 0b10000000) == 0)
		{
			error = "masking is required";
			errorCode = 1002;
			break;
		}

		// Packet length is three forms in WebSocket; 8-bit (<126), 16-bit (126), and 64-bit (127).
		// We don't expect user to send >65kb message via Bluewing, WebSocket or not.
		// It's possible we could read it anyway if it's less than 4GB, but the
		// Bluewing level ping timeout will make sending big packets dangerous anyway.
		lw_i32 packetLen = data[1] & 0b01111111;
		if (packetLen == 127)
		{
			error = "message too big for Bluewing";
			errorCode = 1009; // 1009 = message too big
			break;
		}

		data_remove_prefix(2);
		if (packetLen == 126)
		{
			// Control opcodes like close, ping etc, must be <= 125
			// Only non-control opcode after all those ifs above is 2, binary message
			if (opcode != 2)
			{
				error = "control codes can only be 1 byte long";
				errorCode = 1002;
				break;
			}

			// Packet is too small to necessitate a 2-byte size
			if (size < 2 + 4 + 126)
			{
				// Pretend we haven't read anything, so this header comes back, but with more data behind it
				// This is necessary due to Firefox sending big WS packets as one network packet with just WS header,
				// with next packet data.
				// TODO: Performance: WebSocket large packet processing will be faster if we actually store the read part here, like MessageReader does.
				return 0;
			}

			packetLen = ntohs(*(unsigned short*)&data[0]);
			data_remove_prefix(sizeof(unsigned short));

			// Packet is too small to necessitate a 2-byte size, or does not match size specified
			if (packetLen < 126 || size < 4 + (size_t)packetLen)
			{
				error = "message too small to be valid";
				errorCode = 1002;
				break;
			}
		}

		// Read mask; RFC says it is random, but doesn't prevent this being zero
		lw_ui32 mask = *(lw_ui32*)data;
		data_remove_prefix(sizeof(lw_ui32));

		// Unmask the packet
		unmaskedData = (char *)malloc(size);
		if (unmaskedData == NULL)
		{
			error = "out of memory";
			errorCode = 1002;
			break;
		}
		for (size_t i = 0; i < size; ++i)
			unmaskedData[i] = data[i] ^ ((char *)&mask)[i % 4];

		// If we've started a disconnect (!= -1), we'll ignore everything except an acknowledging close response.
		// (if the client is dodgy and won't acknowledge, they'll get timed out anyway)
		if (client->local_close_code == -1)
		{
			// Binary message - make sure there's content
			if (opcode == 2 && size > 0)
				webserver->on_websocket_message(webserver, client, unmaskedData, size);
			// WebSocket layer ping
			// Bluewing doesn't actually use the WebSocket ping, because if the Fusion app crashes, the browser will keep the socket alive,
			// responding to WebSocket pings, but the app will be unresponsive.
			// So it's better to send the ping on the Blue level and make sure the Fusion app is alive on the other end.
			// However, the browser could send its own pings, so we'll respond as expected.
			else if (opcode == 9)
			{
				error2[0] = (char)0b10001010; // fin + pong
				error2[1] = (char)size; // msg size (no mask); note control frames like ping are hard-capped to < 125 bytes
				memcpy(error2 + 2, unmaskedData, size);
				lwp_stream_write((lw_stream)client->client.socket, error2, 2 + size, 0);
			}
			// WebSocket layer pong
			else if (opcode == 10) {
				lwp_trace("Got WebSocket ping response!");
			}
		}
		// Close connection opcode - usually a 6-byte minimum message, but WebSocket spec allows
		// an optional two-byte reason code, and optionally UTF-8 text, up to 123 bytes long.
		// WebSocket expects the other end to reply with a close packet for a "clean" disconnect.
		if (opcode == 8)
		{
			lw_ui16 remote_code_reason = 1000;
			const char * reason = "(none given)";

			// Close reason was specified, read it
			if (size >= 2)
			{
				remote_code_reason = ntohs(*(lw_ui16*)unmaskedData);

				// More data? Should be a UTF-8 close reason.
				// (if it's not UTF-8, they're already closing the connection with this close packet)
				if (size > 2 && lw_u8str_validate(&unmaskedData[2], size - 2))
					reason = &unmaskedData[2];
			}

			// Not a normal disconnect code, report as error
			if (remote_code_reason != 1000)
			{
				lw_error error = lw_error_new();
				lw_error_addf(error, "Client disconnected; error code %hu, reason \"%s\".", remote_code_reason, reason);
				webserver->on_error(webserver, error);
				lw_error_delete(error);
			}

			// Log close reason; req_disconnect will send our WebSocket close packet, then close connection immediately
			client->remote_close_code = (lw_i16)remote_code_reason;
			lwp_ws_websocket_disconnect(client, 1000);
		}

		free(unmaskedData);
		return originalSize;
	} while (lw_false);

	// Protocol error - client is suspect, starts a WebSocket disconnect, and disconnect timeout
	if (error != NULL)
	{
		lw_error err = lw_error_new();
		lw_error_addf(err, "Disconnecting client %s due to %s.",
			lw_addr_tostring(lw_server_client_remote_addr(client->client.socket), lw_addr_tostring_flags_default),
			error);
		if (webserver->on_error)
			webserver->on_error(webserver, err);
		lw_error_delete(err);
		lwp_ws_websocket_disconnect(client, errorCode);
	}
	free(unmaskedData);
	return originalSize;
}

static void start_timer (lw_ws ctx)
{
	  if (lw_timer_started (ctx->timer))
		 return;

	  lw_timer_start (ctx->timer, ctx->timeout * 1000);
}

static void on_timer_tick (lw_timer timer)
{
	lw_server_client client_socket, next = 0;
	lwp_ws_client client;
	lw_ws ws = (lw_ws) lw_timer_tag (timer);

	for (client_socket = lw_server_client_first (ws->socket);
		 client_socket;
		client_socket = next)
	{
		client = (lwp_ws_client) lw_stream_tag ((lw_stream) client_socket);

		// Load next before tick, in case tick() causes client free(), so client->next is invalid
		next = lw_server_client_next(client_socket);
		client->tick(client);
	}

	for (client_socket = lw_server_client_first (ws->socket_secure);
		 client_socket;
		client_socket = next)
	{
	  client = (lwp_ws_client) lw_stream_tag ((lw_stream) client_socket);

	  // Load next before tick, in case tick() causes client free(), so client->next is invalid
	  next = lw_server_client_next(client_socket);
	  client->tick(client);
	}
}

lw_ws lw_ws_new (lw_pump pump)
{
	lw_ws ctx = (lw_ws) calloc (sizeof (*ctx), 1);

	if (!ctx)
	  return 0;

	lwp_init ();

	ctx->pump = pump;
	ctx->auto_finish = lw_true;
	ctx->timeout = 5; // time to respond to first request

	ctx->timer = lw_timer_new (ctx->pump, "webserver timer");
	lw_timer_set_tag (ctx->timer, ctx);
	lw_timer_on_tick (ctx->timer, on_timer_tick);

	ctx->socket = lw_server_new (pump);
	lw_server_set_tag (ctx->socket, ctx);

	lw_server_on_connect (ctx->socket, on_connect);
	lw_server_on_disconnect (ctx->socket, on_disconnect);
	lw_server_on_error (ctx->socket, on_error);

	ctx->socket_secure = lw_server_new (pump);
	lw_server_set_tag (ctx->socket_secure, ctx);

	lw_server_on_connect (ctx->socket_secure, on_connect);
	lw_server_on_disconnect (ctx->socket_secure, on_disconnect);
	lw_server_on_error (ctx->socket_secure, on_error);

	lw_server_add_npn (ctx->socket_secure, "http/1.1");
	lw_server_add_npn (ctx->socket_secure, "http/1.0");

	start_timer (ctx);

	return ctx;
}

void lw_ws_delete (lw_ws ctx)
{
	if (!ctx)
	  return;

	lw_ws_unhost (ctx);
	lw_ws_unhost_secure (ctx);

	lw_server_delete (ctx->socket);
	lw_server_delete (ctx->socket_secure);

	lw_timer_delete (ctx->timer);

	free (ctx);
}

void lw_ws_host (lw_ws ctx, long port)
{
	lw_filter filter = lw_filter_new ();
	lw_filter_set_local_port (filter, port);

	lw_ws_host_filter (ctx, filter);

	lw_filter_delete (filter);
}

void lw_ws_host_filter (lw_ws ctx, lw_filter filter)
{
	if (!lw_filter_local_port (filter))
	  lw_filter_set_local_port (filter, 80);

	lw_server_host_filter (ctx->socket, filter);
}

void lw_ws_host_secure (lw_ws ctx, long port)
{
	lw_filter filter = lw_filter_new ();
	lw_filter_set_local_port (filter, port);

	lw_ws_host_secure_filter (ctx, filter);

	lw_filter_delete (filter);
}

void lw_ws_host_secure_filter (lw_ws ctx, lw_filter filter)
{
	if(!lw_ws_cert_loaded (ctx))
	  return;

	if (!lw_filter_local_port (filter))
	  lw_filter_set_local_port (filter, 443);

	lw_server_host_filter (ctx->socket_secure, filter);
}

void lw_ws_unhost (lw_ws ctx)
{
	lw_server_unhost (ctx->socket);
}

void lw_ws_unhost_secure (lw_ws ctx)
{
	lw_server_unhost (ctx->socket_secure);
}

lw_bool lw_ws_hosting (lw_ws ctx)
{
	return lw_server_hosting (ctx->socket);
}

lw_bool lw_ws_hosting_secure (lw_ws ctx)
{
	return lw_server_hosting (ctx->socket_secure);
}

int lw_ws_port (lw_ws ctx)
{
	return lw_server_port (ctx->socket);
}

int lw_ws_port_secure (lw_ws ctx)
{
	return lw_server_port (ctx->socket_secure);
}

lw_bool lw_ws_load_cert_file (lw_ws ctx, const char * filename_certchain, const char* filename_privkey,
							  const char * passphrase)
{
	return lw_server_load_cert_file (ctx->socket_secure, filename_certchain, filename_privkey, passphrase);
}

lw_bool lw_ws_load_sys_cert (lw_ws ctx, const char * common_name,
										const char * location,
										const char * store_name)
{
	return lw_server_load_sys_cert (ctx->socket_secure,
									common_name, location, store_name);
}

lw_bool lw_ws_cert_loaded (lw_ws ctx)
{
	return lw_server_cert_loaded (ctx->socket_secure);
}

time_t lw_ws_cert_expiry_time (lw_ws ctx)
{
	return lw_server_cert_expiry_time (ctx->socket_secure);
}

void lw_ws_enable_manual_finish (lw_ws ctx)
{
	ctx->auto_finish = lw_false;
}

void lw_ws_set_idle_timeout (lw_ws ctx, long seconds)
{
	ctx->timeout = seconds;

	if (lw_timer_started (ctx->timer))
	{
	  lw_timer_stop (ctx->timer);
	  start_timer (ctx);
	}
}

long lw_ws_idle_timeout (lw_ws ctx)
{
	return ctx->timeout;
}

void * lw_ws_tag (lw_ws ctx)
{
	return ctx->tag;
}

void lw_ws_set_tag (lw_ws ctx, void * tag)
{
	ctx->tag = tag;
}

lwp_def_hook (ws, get)
lwp_def_hook (ws, post)
lwp_def_hook (ws, head)
lwp_def_hook (ws, error)
lwp_def_hook (ws, upload_start)
lwp_def_hook (ws, upload_chunk)
lwp_def_hook (ws, upload_done)
lwp_def_hook (ws, upload_post)
lwp_def_hook (ws, disconnect)
lwp_def_hook (ws, websocket_message)
lwp_def_hook (ws, websocket_accept)
lwp_def_hook (ws, websocket_connect)
lwp_def_hook (ws, websocket_disconnect)

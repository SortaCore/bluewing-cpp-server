/* vim: set noet ts=4 sw=4 sts=4 ft=c:
 *
 * Copyright (C) 2013 James McLaughlin et al.
 * Copyright (C) 2012-2026 Darkwire Software.
 * All rights reserved.
 *
 * liblacewing and Lacewing Relay/Blue source code are available under MIT license.
 * https://opensource.org/license/mit
*/

#include "../../common.h"
#include "ssl.h"

// MSVC CRT debug memory does not have workarounds for malloca
#ifdef _CRTDBG_MAP_ALLOC
	#define _malloca(x) malloc(x)
	#define _freea(x) free(x)
#endif
// Built into MSVC, but not others
#ifndef _countof
	#define _countof(x) (sizeof(x) / sizeof(x[0]))
#endif
#ifndef SP_PROT_TLS1_3_SERVER
	#define SP_PROT_TLS1_3_SERVER 0x00001000
#endif

// Encrypting outbound stream; depends on handshake done by inbound stream
static size_t def_outbound_sink_data(lw_stream outbound, const char * buffer, size_t size)
{
	lwp_ssl ctx = container_of(outbound, struct _lwp_ssl, outbound);

	// can't send anything until inbound finishes handshake
	if (!ctx->handshake_complete)
		return 0;

	// We cannot encrypt in-place, as the buffer is const, and anything reading back from it will get indecipherable data
	// In Blue, this caused a bug when a secure WebSocket client was in peer list, a peer join/leave would be sent to all
	// before WS client fine, but the encryption would corrupt the message for clients after.
	BYTE* copy = _malloca(size);
	if (!copy)
	{
		lw_error err = lw_error_new();
		lw_error_addf(err, "Out of memory, couldn't alloc %zu bytes", size);
		lw_error_addf(err, "Encrypting message failed");
		if (ctx->handle_error && ctx->client)
			ctx->handle_error(ctx->client, err);
		lw_error_delete(err);
		return size;
	}
	memcpy(copy, buffer, size);

	// 4 buffers required for EncryptMessage, in this exact order
	SecBuffer buffers [4];

	  buffers [0].pvBuffer = ctx->header;
	  buffers [0].cbBuffer = ctx->sizes.cbHeader;
	  buffers [0].BufferType = SECBUFFER_STREAM_HEADER;

	  buffers [1].pvBuffer = copy;
	  buffers [1].cbBuffer = (unsigned long)size;
	  buffers [1].BufferType = SECBUFFER_DATA;

	  buffers [2].pvBuffer = ctx->trailer;
	  buffers [2].cbBuffer = ctx->sizes.cbTrailer;
	  buffers [2].BufferType = SECBUFFER_STREAM_TRAILER;

	  buffers [3].BufferType = SECBUFFER_EMPTY;
	  // MSDN example doesn't bother initing 3 fully

	SecBufferDesc buffers_desc = {0};

	buffers_desc.cBuffers = _countof(buffers);
	buffers_desc.pBuffers = buffers;
	buffers_desc.ulVersion = SECBUFFER_VERSION;

	SECURITY_STATUS status = EncryptMessage(&ctx->context, 0, &buffers_desc, 0);

	if (status != SEC_E_OK)
	{
		_freea(copy);
		lw_error err = lw_error_new();
		lw_error_add(err, status);
		lw_error_addf(err, "Encrypting message failed");
		if (ctx->handle_error && ctx->client)
			ctx->handle_error(ctx->client, err);
		lw_error_delete(err);

		return size;
	}

	// 4th buffer is internal usage only, not output
	for (const SecBuffer * b = buffers; b != buffers + (_countof(buffers) - 1); ++b)
		if (b->cbBuffer > 0)
			lw_stream_data(outbound, (char *)b->pvBuffer, b->cbBuffer);

	_freea(copy);
	return size;
}

// Decrypting inbound stream; also handles TLS handshake and notifying outbound when handshake is done
static size_t def_inbound_sink_data(lw_stream inbound, const char * buffer, size_t input_left)
{
	lwp_ssl ctx = container_of(inbound, struct _lwp_ssl, inbound);

	size_t processed = 0;

	if (!ctx->handshake_complete)
	{
		processed += ctx->proc_handshake_data(ctx, buffer, input_left);

		// Need more data before handshake is done
		if (!ctx->handshake_complete)
			return processed;

		// We read some data for the handshake, so advance the buffer
		buffer += processed;
		input_left -= processed;

		// Now our incoming inbound has finished handshake, tell outbound to try sending again
		lw_stream_retry(&ctx->outbound, lw_stream_retry_now);
	}
	if (input_left == 0)
		return processed;

	// Process the incoming message data. 4 buffers are required.
	SecBuffer buffers[4];

	buffers[0].pvBuffer = (BYTE*)buffer;
	buffers[0].cbBuffer = (unsigned long)input_left;
	buffers[0].BufferType = SECBUFFER_DATA;

	buffers[1].BufferType = SECBUFFER_EMPTY;
	buffers[2].BufferType = SECBUFFER_EMPTY;
	buffers[3].BufferType = SECBUFFER_EMPTY;

	SecBufferDesc buffers_desc = { 0 };

	buffers_desc.cBuffers = _countof(buffers);
	buffers_desc.pBuffers = buffers;
	buffers_desc.ulVersion = SECBUFFER_VERSION;

	ctx->status = DecryptMessage(&ctx->context, &buffers_desc, 0, 0);

	// Not enough input to decrypt
	if (ctx->status == SEC_E_INCOMPLETE_MESSAGE)
		return processed;

	// TLS context was closed by peer; this is a clean shutdown on the TLS level,
	// as opposed to the TCP level.
	if (ctx->status == SEC_I_CONTEXT_EXPIRED)
	{
		lw_error err = lw_error_new();
		lw_error_add(err, ctx->status);
		lw_error_addf(err, "Secure content expired");
		if (ctx->handle_error)
			ctx->handle_error(ctx->client, err);
		lw_error_delete(err);
		return input_left + processed; // Eat the entire thing
	}

	if (ctx->status == SEC_I_RENEGOTIATE)
	{
		ctx->handshake_complete = lw_false;

		/* Schannel may leave the next handshake token in SECBUFFER_EXTRA,
		   to be submitted as a handshake token.
		   If it did not return EXTRA, the modified input buffer is the token. */
		const char* handshake_buffer = buffer;
		size_t handshake_size = input_left, handshake_offset = 0;
		for (const SecBuffer * b = buffers; b != buffers + _countof(buffers); ++b)
		{
			if (b->BufferType == SECBUFFER_EXTRA)
			{
				assert(b->cbBuffer > 0); // idiot check
				handshake_buffer = (const char*)b->pvBuffer;
				handshake_size = b->cbBuffer;
				handshake_offset = input_left - handshake_size;
				break;
			}
		}

		// Resubmit the handshake data
		const size_t handshake_processed = ctx->proc_handshake_data(ctx, handshake_buffer, handshake_size);

		processed = handshake_offset + handshake_processed;

		// Now our incoming inbound has finished handshake, tell outbound to try sending again
		if (ctx->handshake_complete)
			lw_stream_retry(&ctx->outbound, lw_stream_retry_now);

		return processed;
	}

	if (FAILED(ctx->status))
	{
		lw_error err = lw_error_new();
		lw_error_add(err, ctx->status);
		lw_error_addf(err, "Error decrypting the message");
		if (ctx->handle_error)
			ctx->handle_error(ctx->client, err);
		lw_error_delete(err);
		return processed + input_left;
	}

	// We expect 0-1 decrypted buffer DATA, 0-1 extra unprocessed input EXTRA,
	// and it's not worth tracking match count when the loop is only 4
	processed += input_left;
	for (const SecBuffer* b = buffers; b != buffers + _countof(buffers); ++b)
	{
		// Send decrypted data
		if (b->BufferType == SECBUFFER_DATA)
			lw_stream_data(&ctx->inbound, (char*)b->pvBuffer, b->cbBuffer);
		// Retain extra input that wasn't processed
		else if (b->BufferType == SECBUFFER_EXTRA)
			processed -= b->cbBuffer;
	}

	return processed;
}

const static lw_streamdef def_outbound =
{
	def_outbound_sink_data,
	0, /* sink_stream */
	0, /* retry */
	0, /* is_transparent */
	0, /* close */
	0, /* bytes_left */
	0, /* read */
	0  /* cleanup */
};

const static lw_streamdef def_inbound =
{
	def_inbound_sink_data,
	0, /* sink_stream */
	0, /* retry */
	0, /* is_transparent */
	0, /* close */
	0, /* bytes_left */
	0, /* read */
	0  /* cleanup */
};

void lwp_ssl_init(lwp_ssl ctx, lw_server_client socket)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->status = SEC_I_CONTINUE_NEEDED;

	lwp_stream_init(&ctx->outbound, &def_outbound, 0);
	lwp_stream_init(&ctx->inbound, &def_inbound, 0);

	lw_stream_add_filter_upstream
		((lw_stream)socket, &ctx->outbound, lw_false, lw_true);

	lw_stream_add_filter_downstream
		((lw_stream)socket, &ctx->inbound, lw_false, lw_true);

	/* If Schannel leaves an incomplete TLS record queued, retry it after the
	   next socket read appends more encrypted input. */
	lw_stream_retry(&ctx->inbound, lw_stream_retry_more_data);
}

void lwp_ssl_cleanup(lwp_ssl ctx)
{
	lw_stream_close(&ctx->inbound, lw_true);
	lw_stream_close(&ctx->outbound, lw_true);

	free(ctx->header);
	free(ctx->trailer);
}

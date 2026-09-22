/* vim: set noet ts=4 sw=4 sts=4 ft=cpp:
 *
 * Copyright (C) 2011 James McLaughlin.
 * Copyright (C) 2012-2026 Darkwire Software.
 * All rights reserved.
 *
 * liblacewing and Lacewing Relay/Blue source code are available under MIT license.
 * https://opensource.org/license/mit
*/

#include "MessageBuilder.h"

#ifndef lacewingframebuilder
#define lacewingframebuilder

class framebuilder : public messagebuilder
{
protected:
	static constexpr lw_ui32 frameHeaderSize = 8;
	// 11 is the largest pre-allocated header, WebSocket uses it for >65KiB packets.
	// Standard TCP is one byte type
	// UDP uses a 1 or 3 byte header.
	static constexpr lw_ui32 preallocHdrSize = 11;
	static constexpr lw_ui32 headerPrefixSize = preallocHdrSize - frameHeaderSize;

	void preparefortransmission(bool iswebsocketclient)
	{
		if (tosend)
			return;

		lw_ui32 type = *(lw_ui32 *)(buffer + preallocHdrSize - frameHeaderSize);
		lw_i32 messagesize = size - preallocHdrSize;

		lw_ui32 headersize;

		// We're sending to a websocket client, we need to mash this into WebSocket format
		// WebSocket is close to liblacewing, with size as one byte, then expanding with a second variable.
		// WS requires a specific flag + op byte set.
		if (iswebsocketclient)
		{
			// If we're sending to a websocket client, we must be a server.
			// If we're a server, the UDP header has one byte: the type,
			// and as we switch to websocket mode, we set 0x8 in type to indicate psuedo UDP.
			if (origUDP != UINT32_MAX)
				type = buffer[preallocHdrSize - 1] | 0x8;

			// Since we send text messages to channels and so on, we can't use text opcode for text messages
			constexpr lw_ui8 flagopcode = 0b10000010; // fin flag enabled + binary message

			// WS has no liblacewing header, as it'd be an unnecessary repeat of size.
			// Instead, we include type byte as part of WS message and reuse the size variable.
			++messagesize;

			// WS splits at 126 bytes, becoming a separate u16,
			// then splits at 0xFFFF, becoming sep ui64
			if (messagesize <= 125)
			{
				headersize = 3; // flagopcode, msgsize, type
				tosend = buffer + preallocHdrSize - headersize;

				tosend[1] = (lw_ui8)messagesize;
			}
			else if (messagesize <= 0xFFFF)
			{
				headersize = 5; // flagopcode, msgsize, u16 msgsize, type
				tosend = buffer + preallocHdrSize - headersize;
				tosend[1] = 126; // indicate uint16 following size

				const lw_ui16 tmpmsgsize = htons((lw_ui16)messagesize);
				memcpy(tosend + 2, &tmpmsgsize, sizeof(tmpmsgsize));
			}
			else
			{
				headersize = 11; // flagopcode, msgsize, u64 msgsize, type
				tosend = buffer + preallocHdrSize - headersize;
				tosend[1] = 127; // indicate uint64 following size

				// WebSocket size is 64-bit big endian; include the 1 byte for type
				// No portable htonll(), compiler checks are messy, runtime is slow
				// memset and memcpy skip around that and possible alignment issues
				const lw_ui32 tmpmsgsize = htonl(messagesize);
				memset(tosend + 2, 0, sizeof(lw_ui32));
				memcpy(tosend + 6, &tmpmsgsize, sizeof(tmpmsgsize));
			}

			tosend[0] = flagopcode;
			tosend[headersize - 1] = (lw_ui8)type;
			tosendsize = messagesize - 1 + headersize;

			return;
		}

		// Message size < 254; store as type byte + size byte
		if (messagesize < 0xfe)
		{
			headersize = 2;
			tosend = buffer + preallocHdrSize - headersize;

			tosend[1] = (lw_ui8)messagesize;
		}
		// Message size >= 0xFF and <= 0xFFFF; store as type byte, plus size indicator byte of 254, plus size uint16
		else if (messagesize < 0xffff)
		{
			headersize = 4;
			tosend = buffer + preallocHdrSize - headersize;

			const lw_ui16 tmpmsgsize = (lw_ui16)messagesize;

			tosend[1] = 254;
			memcpy(tosend + 2, &tmpmsgsize, sizeof(tmpmsgsize));
		}
		// Message size > 0xFFFF and <= 0xFFFFFFFF; store as type byte, plus size indicator byte of 255, plus size uint32
		else if ((lw_ui32)messagesize < 0xffffffff)
		{
			headersize = 6;
			tosend = buffer + preallocHdrSize - headersize;

			tosend[1] = 255;
			memcpy(tosend + 2, &messagesize, sizeof(messagesize));
		}
		else
			return;

		// tosend is edited in the if-chain above
		tosend[0] = (lw_ui8)type;
		tosendsize = messagesize + headersize;
	}

	const bool isudpclient;

	lw_ui8* tosend;
	int tosendsize;
	// Holds -1 if unset, or stores the lw_ui8 type; used for swapping a UDP message to WebSocket
	lw_ui32 origUDP;
	// If -1, no config; if 1, WebSocket header was last; if 0, plain TCP/UDP header was last
	lw_i8 wasWebLast;

public:

	framebuilder(bool isudpclient)
		: isudpclient(isudpclient)
	{
		// The dummy byte added should have auto-expand to >= 11 by virtue of add() allocating in 1KiB chunks
		add<lw_ui8>(0);
		assert(allocated >= preallocHdrSize);
		framereset();
	}

	inline void addheader(lw_ui8 type, lw_ui8 variant, bool forudp = false, lw_ui16 udpclientid = -1)
	{
		if (threadOwner != std::this_thread::get_id())
			LacewingFatalErrorMsgBox();

		assert(size == preallocHdrSize && "lacewing framebuilder.addheader() error: adding header to message that already has one.");
		assert(type <= 0xF && variant <= 0xF);

		const lw_ui8 relayType = (type << 4) | variant;

		if (!forudp)
		{
			// 8-byte TCP header
			memset(buffer + preallocHdrSize - frameHeaderSize, 0, frameHeaderSize);
			buffer[preallocHdrSize - frameHeaderSize] = relayType;
			return;
		}

		// UDP header, 1 or 3 bytes; if UDP client, include 2-byte client ID
		lw_ui8 * const udpHeader = buffer + preallocHdrSize - (isudpclient ? 3 : 1);
		udpHeader[0] = relayType;

		if (isudpclient)
			memcpy(udpHeader + 1, &udpclientid, sizeof(udpclientid));
		else
			origUDP = relayType;
	}

	inline void send(lacewing::server_client client, bool clear = true)
	{
		if (threadOwner != std::this_thread::get_id())
			LacewingFatalErrorMsgBox();
		if (wasWebLast == -1 || (client->is_websocket() ? 1 : 0) != wasWebLast)
		{
			wasWebLast = client->is_websocket();
			tosend = nullptr; // or preparefortransmission does nothing
			preparefortransmission(wasWebLast);
		}

		if (wasWebLast)
			lwp_stream_write((lw_stream)client, (char *)tosend, tosendsize, 2 /* lwp_stream_write_ignore_busy */);
		else
			client->write((char *)tosend, tosendsize);

		if (clear)
			framereset();
	}

	inline void send(lacewing::client client, bool clear = true)
	{
		if (threadOwner != std::this_thread::get_id())
			LacewingFatalErrorMsgBox();
		preparefortransmission(false);
		client->write((char *)tosend, tosendsize);

		if (clear)
			framereset();
	}

	inline void revert() {
		// Revert the type byte back to its original
		buffer[preallocHdrSize - 1] = (lw_ui8)origUDP;
		tosend = nullptr;
		tosendsize = 0;
	}

	inline void send(lacewing::udp udp, lacewing::address from, lw_ui32 ifidx, lacewing::address to, bool clear = true)
	{
		if (threadOwner != std::this_thread::get_id())
			LacewingFatalErrorMsgBox();

		// UDP client sends type + client ID; UDP server sends type alone
		const size_t headerSize = 1 + (isudpclient ? 2 : 0);
		udp->send (from, ifidx, to, (char *)buffer + preallocHdrSize - headerSize, size - preallocHdrSize + headerSize);

		if (clear)
			framereset();
	}

	inline void framereset()
	{
		size = preallocHdrSize;
		tosend = NULL;
		tosendsize = 0;
		origUDP = UINT32_MAX;
		wasWebLast = -1;
#ifdef _DEBUG
		memset(buffer, 0xCD, allocated);
#endif
	}

};

#endif

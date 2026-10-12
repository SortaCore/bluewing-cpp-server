/* vim: set noet ts=4 sw=4 sts=4 ft=c:
 *
 * Copyright (C) 2011, 2012 James McLaughlin et al.
 * Copyright (C) 2012-2026 Darkwire Software.
 * All rights reserved.
 *
 * liblacewing and Lacewing Relay/Blue source code are available under MIT license.
 * https://opensource.org/license/mit
*/

#include "../common.h"
#include "../address.h"
#include <Iphlpapi.h>

const int ideal_pending_receive_count = 16;

#define overlapped_type_send	 1
#define overlapped_type_receive  2

typedef struct _udp_overlapped
{
	OVERLAPPED overlapped;

	char type;

	void * tag;

} * udp_overlapped;

typedef struct _udp_receive_info
{
	WSAMSG winsock_msg;
	WSABUF winsock_buffer;
	char buffer [lwp_default_buffer_size + 1];

	// Hold either packet-info type with alignment for WSACMSGHDR and its payload.
	union {
		WSACMSGHDR align;
		char data[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo)) + WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
	} control;

	struct sockaddr_storage from;

} * udp_receive_info;

static udp_receive_info udp_receive_info_new ()
{
	udp_receive_info info = (udp_receive_info) calloc (sizeof (*info), 1);

	if (!info)
		return NULL;

	info->winsock_msg.lpBuffers = &info->winsock_buffer;
	info->winsock_msg.dwBufferCount = 1;
	info->winsock_msg.name = (LPSOCKADDR)&info->from;
	info->winsock_msg.namelen = sizeof (info->from);
	info->winsock_msg.Control.buf = info->control.data;
	info->winsock_msg.Control.len = sizeof(info->control.data);
	info->winsock_buffer.buf = info->buffer;
	info->winsock_buffer.len = sizeof (info->buffer) - 1;

	return info;
}

struct _lw_udp
{
	lwp_refcounted;

	lw_pump pump;
	lw_pump_watch pump_watch;

	lw_udp_hook_data on_data;
	lw_udp_hook_error on_error;

	lw_filter filter;

	lw_ui16 port;

	SOCKET socket;
	SOCKET icmpsocket;
	SOCKET icmpv6socket;

	lw_list(udp_overlapped, pending_receives);

	long receives_posted;

	long writes_posted;

	void * tag;

	// Function for sending with a specified outgoing address. Null on WinXP.
	fn_WSASendMsg WSASendMsgPtr;
	// Function for receiving msg and storing its local destination; required even on XP.
	fn_WSARecvMsg WSARecvMsgPtr;
};

// Returns true if lw_udp was freed.
static lw_bool read_completed(lw_udp ctx)
{
	--ctx->receives_posted;
	return lwp_release(ctx, "udp read");
}

// Returns true if lw_udp was freed.
static lw_bool write_completed(lw_udp ctx)
{
	--ctx->writes_posted;
	return lwp_release(ctx, "udp write");
}

static void post_receives (lw_udp ctx)
{
	while (ctx->receives_posted < ideal_pending_receive_count)
	{
		if (ctx->socket == -1)
			break;

		udp_receive_info receive_info = udp_receive_info_new ();

		if (!receive_info)
			break;

		udp_overlapped overlapped =
			(udp_overlapped) calloc (sizeof (*overlapped), 1);

		if (!overlapped)
		{
			free(receive_info);
			break;
		}

		overlapped->type = overlapped_type_receive;
		overlapped->tag = receive_info;

		lwp_retain(ctx, "udp read");

		int res = ctx->WSARecvMsgPtr(ctx->socket,
			&receive_info->winsock_msg,
			NULL,
			&overlapped->overlapped,
			0);

		if (res == SOCKET_ERROR)
		{
			int error = WSAGetLastError();

			if (error != WSA_IO_PENDING)
			{
				free(receive_info);
				free(overlapped);
				lwp_release(ctx, "udp read");

				lw_error err = lw_error_new();
				lw_error_addf(err, "Error posting UDP receive");
				lw_error_add(err, error);
				if (ctx->on_error)
					ctx->on_error(ctx, err);
				lw_error_delete(err);
				break;
			}
			// else no error, running as async

			// fall through
		}
		// else no error, running as sync

		list_push(udp_overlapped, ctx->pending_receives, overlapped);
		++ ctx->receives_posted;
	}
}

static void udp_socket_completion (void * tag, OVERLAPPED * _overlapped,
									unsigned long bytes_transferred, int error)
{
	lw_udp ctx = (lw_udp) tag;

	udp_overlapped overlapped = (udp_overlapped) _overlapped;

	switch (overlapped->type)
	{
		case overlapped_type_send:
		{
			// Send errors should be reported at sendto/sendmsg
			if (error != 0 && !lwp_op_aborted(error))
				always_log("Error in sending message: %d.\n", error);
			write_completed(ctx);
			break;
		}

		case overlapped_type_receive:
		{
			udp_receive_info info = (udp_receive_info) overlapped->tag;

			if (error == 0)
			{
				struct _lw_addr remoteAddr = { 0 };
				lwp_addr_set_sockaddr(&remoteAddr, info->winsock_msg.name);

				// If address doesn't match filter, it's a UDP message from unauthorised source.
				// There's no way to block UDP messages like that on Lacewing's side; firewall perhaps,
				// but user is unlikely to link up automatic firewall changes to Lacewing's error reports.
				// To avoid flooding server with reports, we don't report in release builds.
				if (!lw_filter_check_remote_addr(ctx->filter, &remoteAddr))
				{
#ifdef _lacewing_debug
					lw_addr filter_addr = lw_filter_remote(ctx->filter);
					lwp_trace("UDP from unexpected source \"%s\", outside of filter \"%s\".\n",
						lw_addr_tostring(&remoteAddr, lw_addr_tostring_flags_default),
						lw_addr_tostring(filter_addr, lw_addr_tostring_flags_default));
#endif // _lacewing_debug
				}
				else
				{
					struct _lw_addr localAddr = { 0 };
					lw_ui32 ifIdx = 0;

					// A reply needs the received local destination and interface; never deliver without them
					if (info->winsock_msg.dwFlags & MSG_CTRUNC)
						goto packet_info_error;

					// A mapped IPv4 sender uses IPv4 packet information on a dual-stack socket.
					const lw_bool ipv4 = remoteAddr.info->ai_family == AF_INET ||
						(remoteAddr.info->ai_family == AF_INET6 &&
						IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)remoteAddr.info->ai_addr)->sin6_addr));
					for (WSACMSGHDR* hdr = WSA_CMSG_FIRSTHDR(&info->winsock_msg); hdr;
						hdr = WSA_CMSG_NXTHDR(&info->winsock_msg, hdr))
					{
						struct sockaddr_storage store = { 0 };
						if (ipv4 && hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == IP_PKTINFO &&
							hdr->cmsg_len >= WSA_CMSG_LEN(sizeof(struct in_pktinfo)))
						{
							const struct in_pktinfo* pktInfo = (const struct in_pktinfo*)WSA_CMSG_DATA(hdr);
							struct sockaddr_in* addr = (struct sockaddr_in*)&store;
							addr->sin_family = AF_INET;
							addr->sin_addr = pktInfo->ipi_addr;
							addr->sin_port = htons(ctx->port);
							ifIdx = pktInfo->ipi_ifindex;
						}
						else if (!ipv4 && hdr->cmsg_level == IPPROTO_IPV6 && hdr->cmsg_type == IPV6_PKTINFO &&
							hdr->cmsg_len >= WSA_CMSG_LEN(sizeof(struct in6_pktinfo)))
						{
							const struct in6_pktinfo* pktInfo = (const struct in6_pktinfo*)WSA_CMSG_DATA(hdr);
							struct sockaddr_in6* addr = (struct sockaddr_in6*)&store;
							addr->sin6_family = AF_INET6;
							addr->sin6_addr = pktInfo->ipi6_addr;
							addr->sin6_port = htons(ctx->port);
							ifIdx = pktInfo->ipi6_ifindex;
						}
						else
							continue;
						lwp_addr_set_sockaddr(&localAddr, (struct sockaddr*)&store);
						break;
					}

					if (!localAddr.info)
						goto packet_info_error;
					if (ctx->on_data)
					{
						// Just for defensiveness; won't help with UTF-16 though
						info->buffer[bytes_transferred] = 0;
						ctx->on_data(ctx, &localAddr, ifIdx, &remoteAddr, info->buffer, bytes_transferred);
					}
					goto packet_info_done;

				packet_info_error:
					{
						lw_error err = lw_error_new();
						if (info->winsock_msg.dwFlags & MSG_CTRUNC)
							lw_error_addf(err, "UDP receive control data was truncated");
						else
							lw_error_addf(err, "UDP receive packet information was missing");
						if (ctx->on_error)
							ctx->on_error(ctx, err);
						lw_error_delete(err);
					}
				packet_info_done:
					lwp_addr_cleanup(&localAddr);
				}

				lwp_addr_cleanup(&remoteAddr);
			}
			// else, an error. Ignore op aborted, it indicates socket was closed abruptly
			// by something higher up, i.e. udp unhost.
			else if (!lwp_op_aborted(error))
			{
				lw_error err = lw_error_new();
				lw_error_addf(err, "Error receiving datagram (completion)");
				lw_error_add(err, error);

				if (ctx->on_error)
					ctx->on_error(ctx, err);
				lw_error_delete(err);
			}

			free (info);

			list_remove(udp_overlapped, ctx->pending_receives, overlapped);

			// read_completed may free ctx (and thus return true); if not, post more receives
			if (!read_completed(ctx) && error == 0)
				post_receives(ctx);
			break;
		}
		default:
		{
			lw_error err = lw_error_new();
			lw_error_addf(err, "Error with udp completion, unrecognised type %hhi; %p, %lu, %d",
				overlapped->type, overlapped, bytes_transferred, error);
			if (ctx->on_error)
				ctx->on_error(ctx, err);
			lw_error_delete(err);
			return; // leak in case pointer is invalid
		}
	};

	free (overlapped);
}

void lw_udp_host (lw_udp ctx, lw_ui16 port)
{
	lw_filter filter = lw_filter_new ();
	lw_filter_set_local_port (filter, port);

	lw_udp_host_filter (ctx, filter);

	lw_filter_delete (filter);
}

void lw_udp_host_addr (lw_udp ctx, lw_addr addr, lw_ui16 local_port /* = 0 */)
{
	lw_filter filter = lw_filter_new ();

	if (local_port != 0)
	{
		lw_filter_set_local_port(filter, local_port);
		lw_filter_set_reuse(filter, lw_true);
	}

	lw_filter_set_remote (filter, addr);

	lw_filter_set_ipv6 (filter, lw_addr_ipv6 (addr));

	lw_udp_host_filter (ctx, filter);

	lw_filter_delete (filter);
}

void lw_udp_host_filter (lw_udp ctx, lw_filter filter)
{
	if (ctx->socket != INVALID_SOCKET)
		lw_udp_unhost(ctx);

	lw_error error = lw_error_new ();
	lw_bool madeipv6;

	if ((ctx->socket = lwp_create_server_socket
			(filter, SOCK_DGRAM, IPPROTO_UDP, &madeipv6, error)) == -1)
	{
		if (ctx->on_error)
			ctx->on_error (ctx, error);
		lw_error_delete (error);

		return;
	}
	lw_log_if_debug("Hosted UDP port %d for %s.\n", (int)ctx->socket, madeipv6 ? "IPv6 + mapped IPv4" : "IPv4");

	// Receiving packet information requires WSARecvMsg, including on XP.
	ctx->WSARecvMsgPtr = compat_WSARecvMsg(ctx->socket);
	if (!ctx->WSARecvMsgPtr)
	{
		lw_udp_unhost(ctx);
		lw_error_addf(error, "WSARecvMsg is unavailable for this UDP socket");
		if (ctx->on_error)
			ctx->on_error(ctx, error);
		else
			always_log("%s\n", lw_error_tostring(error));
		lw_error_delete(error);
		return;
	}

	if (madeipv6 && (ctx->icmpv6socket = lwp_create_server_socket
		(filter, SOCK_RAW, IPPROTO_ICMPV6, NULL, error)) == -1)
	{
		lw_error_addf(error, "Creating ICMPv6 socket");
		if (ctx->on_error)
			ctx->on_error(ctx, error);
		// Non-fatal, we don't need ICMP
	}
	lw_filter ipv4filt = lw_filter_clone(filter);
	lw_filter_set_ipv6(ipv4filt, lw_false);
	if ((ctx->icmpsocket = lwp_create_server_socket
		(ipv4filt, SOCK_RAW, IPPROTO_ICMP, NULL, error)) == -1)
	{
		lw_error_addf(error, "Creating ICMPv4 socket");
		if (ctx->on_error)
			ctx->on_error(ctx, error);
		// Non-fatal, we don't need ICMP
	}
	lw_filter_delete(ipv4filt);

	lw_error_delete (error);

	ctx->filter = lw_filter_clone (filter);

	ctx->port = lwp_socket_port(ctx->socket);

	// Not available on WinXP, but all IPv6 stuff is half-baked there
	ctx->WSASendMsgPtr = compat_WSASendMsg();

	ctx->pump_watch = lw_pump_add (ctx->pump, (HANDLE) ctx->socket, "lw_udp_host", ctx, udp_socket_completion);

	post_receives (ctx);
}

lw_bool lw_udp_hosting (lw_udp ctx)
{
	return ctx->socket != INVALID_SOCKET;
}

void lw_udp_unhost (lw_udp ctx)
{
	if (!lw_udp_hosting(ctx))
		return;

	SOCKET s = ctx->socket;
	ctx->socket = INVALID_SOCKET;
	lwp_close_socket (s);

	if (ctx->icmpv6socket != -1)
	{
		s = ctx->icmpv6socket;
		ctx->icmpv6socket = INVALID_SOCKET;
		lwp_close_socket(s);
	}

	if (ctx->icmpsocket != -1)
	{
		s = ctx->icmpsocket;
		ctx->icmpsocket = INVALID_SOCKET;
		lwp_close_socket(s);
	}

	lw_filter_delete (ctx->filter);
	ctx->filter = 0;
}

lw_ui16 lw_udp_port (lw_udp ctx)
{
	return ctx->port;
}

// Called by refcounter when it reaches zero
static void lw_udp_dealloc(lw_udp ctx)
{
	// No refs, so there should be no pending read/writes
	assert(ctx->receives_posted == 0 && ctx->writes_posted == 0);
	list_clear(ctx->pending_receives);

	if (ctx->pump_watch)
	{
		lw_pump_remove(ctx->pump, ctx->pump_watch, "lw_udp_dealloc");
		ctx->pump_watch = NULL;
	}

	free(ctx);
}

lw_udp lw_udp_new (lw_pump pump)
{
	lw_udp ctx = (lw_udp) calloc (sizeof (*ctx), 1);

	if (!ctx)
		return 0;

	lwp_enable_refcount_logging(ctx, "udp");
	lwp_set_dealloc_proc(ctx, lw_udp_dealloc);
	lwp_retain(ctx, "udp new");

	lwp_init ();

	ctx->pump = pump;
	ctx->socket = INVALID_SOCKET;
	ctx->icmpsocket = INVALID_SOCKET;
	ctx->icmpv6socket = INVALID_SOCKET;

	return ctx;
}

void lw_udp_delete (lw_udp ctx)
{
	if (!ctx)
	  return;

	// delete succeeded, ctx is now freed
	if (lwp_release(ctx, "udp new"))
		return;

	if (ctx->socket != INVALID_SOCKET)
		lw_udp_unhost (ctx);

	// memset(ctx, 0, sizeof(_lw_udp));

	lwp_deinit();

	// free (ctx) called by refcount reaching zero
}

void lw_udp_send (lw_udp ctx, lw_addr from, lw_ui32 ifidx, lw_addr to, const char * buffer, size_t size)
{
	if (!to || (!lw_addr_ready (to)) || !to->info)
	{
		lw_error error = lw_error_new ();

		lw_error_addf (error, "The remote address passed to send() wasn't ready");
		lw_error_addf (error, "Error sending datagram");

		if (ctx->on_error)
			ctx->on_error (ctx, error);

		lw_error_delete (error);

		return;
	}

	if (size == -1)
	  size = strlen (buffer);

	if (sizeof(size) > 4)
		assert(size < 0xFFFFFFFF);
	const lw_bool ipv4 = to->info->ai_family == AF_INET ||
		(to->info->ai_family == AF_INET6 &&
		IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)to->info->ai_addr)->sin6_addr));
	if (from)
	{
		const lw_bool source_ready = lw_addr_ready(from) && from->info && from->info->ai_addr;
		const int family = source_ready ? from->info->ai_family : AF_UNSPEC;
		const lw_bool source_ipv4 = family == AF_INET ||
			(family == AF_INET6 &&
			IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)from->info->ai_addr)->sin6_addr));
		if (!source_ready || (family != AF_INET && family != AF_INET6) || source_ipv4 != ipv4)
		{
			lw_error error = lw_error_new();
			lw_error_addf(error, "Cannot send datagram with the requested local source address");
			if (ctx->on_error)
				ctx->on_error(ctx, error);
			lw_error_delete(error);
			return;
		}
	}

	udp_overlapped overlapped = (udp_overlapped) lw_calloc_or_exit (sizeof (*overlapped) + size, 1);

	lwp_retain(ctx, "udp write");
	++ctx->writes_posted;

	overlapped->type = overlapped_type_send;
	memcpy(((char*)overlapped) + sizeof(*overlapped), buffer, size);

	WSABUF winsock_buf = { (ULONG)size, ((CHAR*)overlapped) + sizeof(*overlapped) };

	int res;
	fn_WSASendMsg wsaSendMsg = from ? ctx->WSASendMsgPtr : NULL;
	if (!wsaSendMsg)
	{
		res = WSASendTo(ctx->socket, &winsock_buf, 1, 0, /* MSG_XX flags */ 0, to->info->ai_addr,
			(int)to->info->ai_addrlen, (OVERLAPPED*)overlapped, 0);
	}
	else // specify source address
	{
		assert((int)ifidx > -1);
		union {
			WSACMSGHDR align;
			char data[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))];
		} control = { 0 };
		WSACMSGHDR* cmsg = (WSACMSGHDR*)control.data;
		WSAMSG msg = { 0 };

		msg.name = to->info->ai_addr;
		msg.namelen = (int)to->info->ai_addrlen;

		msg.lpBuffers = &winsock_buf;
		msg.dwBufferCount = 1;
		msg.dwFlags = 0;
		msg.Control.buf = control.data;

		// Packet-info family follows the destination, including IPv4-mapped IPv6.
		if (ipv4)
		{
			msg.Control.len = WSA_CMSG_SPACE(sizeof(struct in_pktinfo));
			cmsg->cmsg_level = IPPROTO_IP;
			cmsg->cmsg_type = IP_PKTINFO;
			cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(struct in_pktinfo));

			struct in_pktinfo* const pktinfo = (struct in_pktinfo*)WSA_CMSG_DATA(cmsg);
			if (from->info->ai_family == AF_INET)
				pktinfo->ipi_addr = ((struct sockaddr_in*)from->info->ai_addr)->sin_addr;
			else
				memcpy(&pktinfo->ipi_addr,
					&((struct sockaddr_in6*)from->info->ai_addr)->sin6_addr.s6_addr[12], sizeof(struct in_addr));
			pktinfo->ipi_ifindex = ifidx;
		}
		else // AF_INET6
		{
			msg.Control.len = WSA_CMSG_SPACE(sizeof(struct in6_pktinfo));
			cmsg->cmsg_level = IPPROTO_IPV6;
			cmsg->cmsg_type = IPV6_PKTINFO;
			cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(struct in6_pktinfo));
			struct in6_pktinfo* const pktinfo = (struct in6_pktinfo*)WSA_CMSG_DATA(cmsg);
			pktinfo->ipi6_addr = ((struct sockaddr_in6*)from->info->ai_addr)->sin6_addr;
			pktinfo->ipi6_ifindex = ifidx;
		}

		res = wsaSendMsg(ctx->socket, &msg, 0, NULL, &overlapped->overlapped, NULL);
	}

	const lw_addr_tostring_flags addrstringflags = lw_addr_tostring_flag_box_ipv6;
	do {
		if (res == SOCKET_ERROR)
		{
			const int code = WSAGetLastError();

			// no error, running as async
			if (code == WSA_IO_PENDING)
				break;

			--ctx->writes_posted;
			free(overlapped);

			// outgoing is overloaded; as it's UDP, just discard the message
			// Closest to the EAGAIN exception on Unix servers, but since we use overlapped, it's unlikely this will apply
			// This code as a response to WSASendTo may be Windows NT only
			if (code == WSAEWOULDBLOCK)
			{
				lwp_release(ctx, "udp write");
				break;
			}

			// genuine error, whine about it
			lw_error error = lw_error_new();
			lw_error_add(error, code);
			lw_error_addf(error, "Error sending datagram via %s", wsaSendMsg ? "sendmsg" : "sendto");
#ifdef _DEBUG
			if (wsaSendMsg)
			{
				lw_error_addf(error, "Sending UDP from socket %i, local address \"%s\", addrlen %i, ifidx %u), to remote \"%s\" (addrlen %i)",
					(int)ctx->socket,
					lw_addr_tostring(from, addrstringflags),
					from->info->ai_addrlen,
					ifidx,
					lw_addr_tostring(to, addrstringflags),
					to->info->ai_addrlen);
			}
			else
			{
				lw_error_addf(error, "Sending from OS default local address/interface, to remote \"%s\" (addrlen %i)",
					lw_addr_tostring(to, addrstringflags), to->info->ai_addrlen);
			}
#endif

			if (ctx->on_error)
				ctx->on_error(ctx, error);

			lw_error_delete(error);
			lwp_release(ctx, "udp write");
			break;
		}
		// else no error, completed as sync already (IOCP still has posted completion status)
#ifdef _DEBUG
		if (wsaSendMsg)
		{
			lw_log_if_debug("Sending UDP from socket %i, local address \"%s\" net interface ID %u, to remote \"%s\", success (instant).\n",
				(int)ctx->socket,
				lw_addr_tostring(from, addrstringflags),
				ifidx,
				lw_addr_tostring(to, addrstringflags));
		}
		else
		{
			lw_log_if_debug("Sending from OS default local address/interface, to remote \"%s\", success (instant).\n",
				lw_addr_tostring(to, addrstringflags));
		}
#endif
	} while (0);
}

void lw_udp_send_unreachable(lw_udp ctx, lw_addr from, lw_ui32 ifidx, lw_addr to, const char * data, lw_ui32 size)
{
	lwp_socket icmpsock = lw_addr_ipv6(from) ? ctx->icmpv6socket : ctx->icmpsocket;
	lw_error err;
	if (icmpsock == -1)
	{
		err = lw_error_new();
		lw_error_addf(err, "ICMP%s send error - no socket", lw_addr_ipv6(from) ? "v6" : "v4");
		if (ctx->on_error)
			ctx->on_error(ctx, err);
		lw_error_delete(err);
	}

	err = lwp_send_icmp_unreachable(icmpsock, IPPROTO_UDP, from, ifidx, to, data, size);
	if (err)
	{
		lw_error_addf(err, "ICMP send error");
		if (ctx->on_error)
			ctx->on_error(ctx, err);
		lw_error_delete(err);
	}
}

void lw_udp_set_tag (lw_udp ctx, void * tag)
{
	ctx->tag = tag;
}

void * lw_udp_tag (lw_udp ctx)
{
	return ctx->tag;
}

lwp_def_hook (udp, error)
lwp_def_hook (udp, data)

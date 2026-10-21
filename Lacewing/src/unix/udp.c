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

struct _lw_udp
{
	lwp_refcounted;
	lw_pump pump;

	lw_udp_hook_data on_data;
	lw_udp_hook_error on_error;

	lw_filter filter;
	lw_pump_watch pump_watch;

	int fd;
	int icmpfd;
	int icmpv6fd;

	long receives_posted;
	// writes_posted is not tracked as they are instantly sent or discarded, unlike windows IOCP

	void * tag;
};

static void read_ready (void * ptr)
{
	lw_udp ctx = (lw_udp)ptr;

	struct sockaddr_storage from;
	socklen_t from_size = sizeof (from);

	char buffer [lwp_default_buffer_size + 1];
	
	// These are needed to get receiving local IP address and interface,
	// so we can reply with UDP on the same
	union {
		struct cmsghdr align;
		char data[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(struct in_pktinfo))];
	} control;
	struct iovec iov = { .iov_base = buffer, .iov_len = lwp_default_buffer_size };
	struct msghdr msg = {
		.msg_control = control.data,
		.msg_controllen = sizeof(control.data),
		.msg_name = &from,
		.msg_namelen = from_size,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_flags = 0,
	};

	lwp_retain(ctx, "udp read");

	struct _lw_addr remote_addr = { 0 }, local_addr = { 0 };

	for (ssize_t bytes, ifidx; ; )
	{
		msg.msg_namelen = sizeof(from);
		msg.msg_controllen = sizeof(control.data);
		msg.msg_flags = 0;
		bytes = recvmsg(ctx->fd, &msg, 0);

		if (bytes == -1)
		{
			// Ignore, we already processed the messages
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			lw_log_if_debug("Error in recvmsg: %d. read_ready ignored.\n", errno);
			break;
		}

		// Success but nothing - 0 bytes of data in UDP datagram?
		if (bytes == 0)
		{
			lw_log_if_debug("Warning from recvmsg: Got 0 bytes. read_ready ignored.\n");
			break;
		}

        // Populate remote_addr from the actual sender's address/port
        lwp_addr_set_sockaddr(&remote_addr, (struct sockaddr*)&from);
		
		// Does not match expected incoming filter, discard it
		if (!lw_filter_check_remote_addr(ctx->filter, &remote_addr))
		{
			lw_log_if_debug("Dropping incoming UDP packet from unexpected remote address \"%s\".\n",
				lw_addr_tostring(&remote_addr, lw_addr_tostring_flag_box_ipv6));
			lwp_addr_cleanup(&remote_addr);
			memset(&remote_addr, 0, sizeof(remote_addr));
			continue;
		}

		// A reply needs the received local destination and interface; never deliver without them.
		ifidx = 0;
		if (msg.msg_flags & MSG_CTRUNC)
			goto packet_info_error;
		
		// A mapped IPv4 sender uses IPv4 packet information on a dual-stack socket.
		const lw_bool ipv4 = from.ss_family == AF_INET ||
			(from.ss_family == AF_INET6 &&
			IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&from)->sin6_addr));
			
		for (struct cmsghdr* hdr = CMSG_FIRSTHDR(&msg); hdr; hdr = CMSG_NXTHDR(&msg, hdr))
		{
			struct sockaddr_storage local = { 0 };
			if (ipv4 && hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == IP_PKTINFO &&
				hdr->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo)))
			{
				const struct in_pktinfo* pktinfo = (const struct in_pktinfo*)CMSG_DATA(hdr);
				struct sockaddr_in* addr = (struct sockaddr_in*)&local;
				addr->sin_family = AF_INET;
				addr->sin_port = htons(lw_udp_port(ctx));
				addr->sin_addr = pktinfo->ipi_addr;
				ifidx = (ssize_t)pktinfo->ipi_ifindex;
			}
			else if (!ipv4 && hdr->cmsg_level == IPPROTO_IPV6 && hdr->cmsg_type == IPV6_PKTINFO &&
				hdr->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo)))
			{
				const struct in6_pktinfo* pktinfo = (const struct in6_pktinfo*)CMSG_DATA(hdr);
				struct sockaddr_in6* addr = (struct sockaddr_in6*)&local;
				addr->sin6_family = AF_INET6;
				addr->sin6_port = htons(lw_udp_port(ctx));
				addr->sin6_addr = pktinfo->ipi6_addr;
				ifidx = (ssize_t)pktinfo->ipi6_ifindex;
			}
			else
				continue; // next pktinfo
			lwp_addr_set_sockaddr(&local_addr, (struct sockaddr*)&local);
			break;
		}
		if (!local_addr.info)
			goto packet_info_error;

		if (ctx->on_data)
		{
			// Just for defensiveness; won't help with UTF-16 though
			buffer [bytes] = 0;
			
			ctx->on_data(ctx, &local_addr, (lw_ui32)ifidx, &remote_addr, buffer, (size_t)bytes);
		}
		goto next_datagram;

	packet_info_error:
		{
			lw_error err = lw_error_new();
			if (msg.msg_flags & MSG_CTRUNC)
				lw_error_addf(err, "UDP receive control data was truncated");
			else
				lw_error_addf(err, "UDP receive packet information was missing");
			if (ctx->on_error)
				ctx->on_error(ctx, err);
			lw_error_delete(err);
		}

	next_datagram:
		lwp_addr_cleanup(&local_addr);
		memset(&local_addr, 0, sizeof(local_addr));

		lwp_addr_cleanup(&remote_addr);
		memset(&remote_addr, 0, sizeof(remote_addr));
	}

	lwp_release(ctx, "udp read");
}

void lw_udp_host (lw_udp ctx, lw_ui16 port)
{
	lw_filter filter = lw_filter_new ();
	lw_filter_set_local_port (filter, port);

	lw_udp_host_filter (ctx, filter);

	lw_filter_delete (filter);
}

void lw_udp_host_addr (lw_udp ctx, lw_addr addr, lw_ui16 local_port)
{
	lw_filter filter = lw_filter_new ();
	lw_filter_set_remote (filter, addr);

	lw_filter_set_ipv6 (filter, lw_addr_ipv6 (addr));

	lw_udp_host_filter (ctx, filter);

	lw_filter_delete (filter);
}

void lw_udp_host_filter (lw_udp ctx, lw_filter filter)
{
	lw_udp_unhost (ctx);

	lw_error error = lw_error_new ();
	lw_bool madeipv6;

	if ((ctx->fd = lwp_create_server_socket
			(filter, SOCK_DGRAM, IPPROTO_UDP, &madeipv6, error)) == -1)
	{
		lw_error_addf(error, "Creating UDP port");
		if (ctx->on_error)
			ctx->on_error (ctx, error);

		lw_error_delete (error);
		return;
	}
	if (madeipv6 && (ctx->icmpv6fd = lwp_create_server_socket
		(filter, SOCK_RAW, IPPROTO_ICMPV6, NULL, error)) == -1)
	{
		lw_error_addf(error, "Creating ICMPv6 port");
		if (ctx->on_error)
			ctx->on_error (ctx, error);

		lw_error_delete (error);
		error = lw_error_new ();
		// non-fatal, we don't need ICMP
	}

	lw_filter_set_ipv6(filter, lw_false);
	if ((ctx->icmpfd = lwp_create_server_socket
		(filter, SOCK_RAW, IPPROTO_ICMP, NULL, error)) == -1)
	{
		lw_error_addf(error, "Creating ICMP port");
		if (ctx->on_error)
			ctx->on_error (ctx, error);
		// non-fatal, we don't need ICMP
	}

	lw_error_delete (error);

	lwp_make_nonblocking(ctx->fd);
	if (ctx->icmpfd != -1)
		lwp_make_nonblocking(ctx->icmpfd);
	if (ctx->icmpv6fd != -1)
		lwp_make_nonblocking(ctx->icmpv6fd);

	ctx->filter = lw_filter_clone (filter);

	ctx->pump_watch = lw_pump_add (ctx->pump, ctx->fd, ctx, read_ready, 0, lw_true);
}

lw_bool lw_udp_hosting (lw_udp ctx)
{
	return ctx->fd != -1;
}

lw_ui16 lw_udp_port (lw_udp ctx)
{
	return lwp_socket_port (ctx->fd);
}

void lw_udp_unhost (lw_udp ctx)
{
	// Hosting and teardown stay on the pump's owning thread; send may run elsewhere.
	lw_pump_thread_check(ctx->pump);

	// pump_watch has an FD, used to cancel pending events, so we don't use close_socket until it's used
	if (ctx->fd != -1)
		shutdown(ctx->fd, SHUT_RDWR);

	lwp_close_socket(ctx->fd);
	lwp_close_socket(ctx->icmpfd);
	lwp_close_socket(ctx->icmpv6fd);
	ctx->icmpfd = ctx->icmpv6fd = ctx->fd = -1;

	lw_filter_delete (ctx->filter);
	ctx->filter = 0;

	// Close pump only after sockets are closed; epoll and kqueue will automatically remove their FDs,
	// but select is also an event model
	lw_pump_remove(ctx->pump, ctx->pump_watch);
	ctx->pump_watch = NULL;
}

lw_udp lw_udp_new (lw_pump pump)
{
	lw_udp ctx = (lw_udp)calloc (sizeof (*ctx), 1);

	if (!ctx)
		return 0;

	lwp_init ();
	lwp_enable_refcount_logging(ctx, "udp");
	lwp_retain(ctx, "udp_new");

	ctx->pump = pump;
	ctx->icmpfd = ctx->icmpv6fd = ctx->fd = -1;

	return ctx;
}

void lw_udp_delete (lw_udp ctx)
{
	if (!ctx)
		return;

	lw_udp_unhost (ctx);

	// We should test if it's freed? But there's not really much the app can do to prevent it,
	// and the better behaviour is to let whatever's using it free it by itself.
	lwp_release(ctx, "udp_new"); // calls free (ctx)
}

void lw_udp_send (lw_udp ctx, lw_addr from, lw_ui32 ifidx, lw_addr to, const char * data, size_t size)
{
	if (!to || (!lw_addr_ready(to)) || !to->info)
	{
		lw_error error = lw_error_new ();

		lw_error_addf (error, "The remote address passed to send() wasn't ready");
		lw_error_addf (error, "Error sending");

		if (ctx->on_error)
			ctx->on_error (ctx, error);

		lw_error_delete (error);

		return;
	}

	if (size == SIZE_MAX)
		size = strlen (data);

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

	lwp_retain(ctx, "udp write");

	// Unlike Windows, Linux copies the data passed to sendmsg in non-blocking IO
	ssize_t res;
	if (from)
	{
		assert((lw_i32)ifidx >= 0); // negative is invalid
		struct iovec iov = { .iov_base = (void*)data, .iov_len = size };
		union {
			struct cmsghdr align;
			char data[CMSG_SPACE(sizeof(struct in6_pktinfo))];
		} control = { 0 };
		struct msghdr msg = {
			.msg_name = to->info->ai_addr,
			.msg_namelen = to->info->ai_addrlen,
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = control.data,
			.msg_flags = 0
		};
		struct cmsghdr* const cmsg = (struct cmsghdr*)control.data;
		// Packet-info family follows the destination, including IPv4-mapped IPv6.
		if (ipv4)
		{
			msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
			cmsg->cmsg_level = IPPROTO_IP;
			cmsg->cmsg_type = IP_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

			struct in_pktinfo* const pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
			if (from->info->ai_family == AF_INET)
				pktinfo->ipi_spec_dst = ((struct sockaddr_in*)from->info->ai_addr)->sin_addr;
			else
				memcpy(&pktinfo->ipi_spec_dst,
					&((struct sockaddr_in6*)from->info->ai_addr)->sin6_addr.s6_addr[12], sizeof(struct in_addr));
			pktinfo->ipi_ifindex = (int)ifidx;
		}
		else // AF_INET6
		{
			msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
			cmsg->cmsg_level = IPPROTO_IPV6;
			cmsg->cmsg_type = IPV6_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

			struct in6_pktinfo* const pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsg);
			pktinfo->ipi6_addr = ((struct sockaddr_in6*)from->info->ai_addr)->sin6_addr;
			pktinfo->ipi6_ifindex = ifidx;
		}

		res = sendmsg(ctx->fd, &msg, 0);
	}
	else
	{
		res = sendto(ctx->fd, data, size, 0, to->info->ai_addr,
			to->info->ai_addrlen);
	}

	// Something went awry
	if (res == -1)
	{
		// Ignore EAGAIN/EWOULDBLOCK since we're sending UDP; if there's not outgoing room
		// to immediately send, then just discard
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			lw_error error = lw_error_new();

			lw_error_add(error, errno);
			lw_error_addf(error, "Error sending to %s from local address %s, ifidx %u",
				lw_addr_tostring(to, lw_addr_tostring_flag_box_ipv6),
				lw_addr_tostring(from, lw_addr_tostring_flag_box_ipv6), ifidx);

			if (ctx->on_error)
				ctx->on_error(ctx, error);

			lw_error_delete(error);
		}

		// fall through to lwp_release
	}

	// Although sendmsg() allows partial write, it's not expected for UDP.
	// The docs on Linux are vague, saying partial writes are possible in general,
	// and explicitly speaking about UDP, but not noting UDP as an exception to that rule.
	// But other places lay out that the meaning of a datagram is all or nothing write, e.g.
	// https://github.com/libuv/libuv/blob/6b5aa669db4d57231e21b1ee97c63a06167e117e/src/unix/udp.c#L458
	// For now we'll assume if res is not -1, it is the full message.

	lwp_release(ctx, "udp write");
}

void lw_udp_send_unreachable(lw_udp ctx, lw_addr from, lw_ui32 ifidx, lw_addr to, const char* data, lw_ui32 size)
{
	if (!from)
		return;
	lwp_socket icmpsock = lw_addr_ipv6(from) ? ctx->icmpv6fd : ctx->icmpfd;
	if (icmpsock == -1)
		return;
	lw_error err = lwp_send_icmp_unreachable(icmpsock, IPPROTO_UDP, from, ifidx, to, data, size);
	if (err)
	{
		lw_error_addf(err, "ICMP error");
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

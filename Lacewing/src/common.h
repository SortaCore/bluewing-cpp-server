/* vim: set noet ts=4 sw=4 sts=4 ft=c:
 *
 * Copyright (C) 2011, 2012, 2013 James McLaughlin.
 * Copyright (C) 2012-2026 Darkwire Software.
 * All rights reserved.
 *
 * liblacewing and Lacewing Relay/Blue source code are available under MIT license.
 * https://opensource.org/license/mit
*/
#pragma once

#define _lacewing_internal

#ifdef _WIN32

	#if defined (_lacewing_vld)
		#include <vld.h>
	#endif

	#if defined(_DEBUG) && !defined(_lacewing_debug)
	  // #define _lacewing_debug
	#endif

	#ifndef _CRT_SECURE_NO_WARNINGS
	  #define _CRT_SECURE_NO_WARNINGS
	#endif

	#ifndef _CRT_NONSTDC_NO_WARNINGS
	  #define _CRT_NONSTDC_NO_WARNINGS
	#endif

	// These deprecation warnings are functionally useless
	#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
	  #define _WINSOCK_DEPRECATED_NO_WARNINGS
	#endif

	#ifdef HAVE_CONFIG_H
	  #include "../config.h"
	#endif
	#include <tchar.h>
	#include <inttypes.h>
	#define ENABLE_THREADS
#else

	#ifndef _GNU_SOURCE
	  #define _GNU_SOURCE
	#endif

	#ifdef HAVE_CONFIG_H
	  #include "../config.h"
	#endif

	// Custom Fusion extension configurations
	#ifdef COXSDK
		#ifdef __ANDROID__
			#include "fusion/android config.h"
		#elif defined(__unix__)
			#include "fusion/unix config.h"
		#elif defined(__APPLE__)
			#include "fusion/ios config.h"
		#else
			#error No configuration file
		#endif
	#endif

	#ifdef HAVE_SYS_SENDFILE_H
		#include <sys/sendfile.h>
	#endif

#endif

#ifdef ENABLE_THREADS
	#ifdef _MSC_VER
		typedef unsigned long lw_thread_id;
		#define lw_thread_id_current() GetCurrentThreadId()
		#define lw_thread_id_equal(a, b) ((a) == (b))
	#elif __STDC_NO_THREADS__==0
		#include <threads.h>
		typedef thrd_t lw_thread_id;
		#define lw_thread_id_current() thrd_current()
		#define lw_thread_id_equal(a, b) thrd_equal((a), (b))
	#elif HAVE_PTHREADS
		#include <pthread.h>
		typedef pthread_t lw_thread_id;
		#define lw_thread_id_current() pthread_self()
		#define lw_thread_id_equal(a, b) pthread_equal((a), (b))
	#else
		#error Threads enabled, but unknown threading model
	#endif
#endif

#ifdef _WIN32
	#ifndef _lacewing_static
	  #define lw_import __declspec(dllexport)
	#endif
#else
	#ifdef __GNUC__
	  #ifndef _lacewing_static
		 #define lw_import __attribute__((visibility("default")))
	  #endif
	#else
	  #define lw_import
	#endif
#endif

#ifdef __cplusplus
extern "C"
#endif
void always_log(const char* c, ...);

/* For convenience, some types (such as lw_client and lw_ws_req) are typedef-d
 * to lw_stream in lacewing.h instead of to their extended structure.  The
 * typedefs here are the internal ones mapping everything to their _real_ type,
 * so that the fields after the lw_stream ones may be accessed inside the
 * library.
 */

 typedef struct _lw_thread			* lw_thread;
 typedef struct _lw_addr			* lw_addr;
 typedef struct _lw_filter			* lw_filter;
 typedef struct _lw_pump			* lw_pump;
 typedef struct _lw_pump_watch		* lw_pump_watch;
 typedef struct _lw_eventpump		* lw_eventpump;
 typedef struct _lw_stream			* lw_stream;
 typedef struct _lw_fdstream		* lw_fdstream;
 typedef struct _lw_file			* lw_file;
 typedef struct _lw_timer			* lw_timer;
 typedef struct _lw_sync			* lw_sync;
 typedef struct _lw_event			* lw_event;
 typedef struct _lw_error			* lw_error;
 typedef struct _lw_client			* lw_client;
 typedef struct _lw_server			* lw_server;
 typedef struct _lw_server_client	* lw_server_client;
 typedef struct _lw_udp				* lw_udp;
 typedef struct _lw_flashpolicy		* lw_flashpolicy;
 typedef struct _lw_ws				* lw_ws;
 typedef struct _lw_ws_req			* lw_ws_req;
 typedef struct _lw_ws_websocket	* lw_ws_websocket;
 typedef struct _lw_ws_req_hdr		* lw_ws_req_hdr;
 typedef struct _lw_ws_req_param	* lw_ws_req_param;
 typedef struct _lw_ws_req_cookie	* lw_ws_req_cookie;
 typedef struct _lw_ws_upload		* lw_ws_upload;
 typedef struct _lw_ws_upload_hdr	* lw_ws_upload_hdr;
 typedef struct _lw_ws_session		* lw_ws_session;
 typedef struct _lw_ws_sessionitem	* lw_ws_sessionitem;

#ifndef _lacewing_h
#include "../Lacewing.h"
#endif

#ifdef _MSC_VER
	#pragma warning(disable: 4200) /* zero-sized array in struct/union */
#endif

#include "list.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>

// Implemented per-plat
void lwp_init ();
void lwp_deinit ();

// Implemented in global.c
void lwp_network_change_init ();
void lwp_network_change_deinit ();
void lwp_on_network_changed (lw_network_change_type how);

#ifdef _lacewing_debug
	#include "refcount-dbg.h"
#else
	#include "refcount.h"
#endif

#ifndef container_of
	#define container_of(p, type, v) \
		((type *)  (((char *) p) - offsetof(type, v)) )

#endif

#include "heapbuffer.h"

#include "../deps/uthash/uthash.h"
#include "nvhash.h"

#define lwp_max_path 512

#ifdef _WIN32
	#include "windows/common.h"
#else
	#include "unix/common.h"
#endif

#if defined(HAVE_MALLOC_H) || defined(_WIN32)
	#include <malloc.h>
#elif defined(HAVE_MALLOC_MALLOC_H)
	#include <malloc/malloc.h>
#endif

#if defined(_lacewing_debug)
	#define lwp_trace lw_trace
#else
	#define lwp_trace(x, ...) (void)0
#endif
// Temp, until we revamp Lacewing logging system to allow excluding some
#ifdef _DEBUG
	#define lw_log_if_debug(x, ...) always_log(x, ## __VA_ARGS__)
#else
	#define lw_log_if_debug lwp_trace
#endif

/* TODO : find the optimal value for this?  make adjustable? */

#define lwp_default_buffer_size (1024 * 64)

#define lwp_setsockopt(f,l,o,oname,olen) lwp_setsockopt2(f,l,o,#o,oname,olen)

#ifdef __cplusplus
extern "C" {
#endif
void lwp_make_nonblocking (lwp_socket socket);
void lwp_setsockopt2 (lwp_socket fd, int level, int option, const char * optionText, const char * value, socklen_t value_length);
void lwp_disable_ipv6_only (lwp_socket socket);

struct sockaddr_storage lwp_socket_addr (lwp_socket socket);

lw_ui16 lwp_socket_port (lwp_socket socket);

void lwp_close_socket (lwp_socket socket);

lw_bool lwp_urldecode (const char * in, size_t in_length,
						char * out, size_t out_length, lw_bool plus_spaces);

lw_bool lwp_begins_with (const char * string, const char * substring);

void lwp_copy_string (char * dest, const char * source, size_t size);

// Replaces memcmp with something that has a useful return index. Returns -1 if both match.
lw_ui32 lw_memcmp_diff_index (const lw_ui8* const a, const lw_ui8* const b, const lw_ui32 size);
lw_bool lwp_find_char (const char ** str, size_t * len, char c);

ssize_t lwp_format (char ** output, const char * format, va_list args);

void lwp_to_lowercase (char * str);

extern const char * const lwp_weekdays [];
extern const char * const lwp_months [];

time_t lwp_parse_time (const char *);

lwp_socket lwp_create_server_socket (lw_filter, int type, int protocol, lw_bool * madeipv6, lw_error);

// Sends a ICMP Port Unreachable message, and reports the result with the handler
lw_error lwp_send_icmp_unreachable(lwp_socket icmpsock, int proto, lw_addr local, lw_ui32 ifidx, lw_addr remote,
	const char* origMsg, lw_ui32 origMsgSize);

extern struct in6_addr lwp_ipv6_public_fixed_addr;
extern int lwp_ipv6_public_fixed_interface_index;
extern void lwp_trigger_public_address_hunt (lw_bool block);
extern lw_bool lwp_set_ipv6pktinfo_cmsg(void * cmsg);

#ifdef __cplusplus

	} /* extern "C" */

	using namespace lacewing;
	#include <new>

#endif

#define lwp_def_hook(c, hook) \
	void lw_##c##_on_##hook (lw_##c ctx, lw_##c##_hook_##hook hook)			\
	{	ctx->on_##hook = hook;												\
	}																		 \

#ifdef _WIN32
	// If we CancelIoEx() or closesocket(), IOCP will produce op aborted for pending overlaps.
	// On Wine, Linux has no overlapped equivalent, so it produces async handles closed.
	// @remarks This is because Wine emulates IOCP using wineserver:
	// https://github.com/wine-mirror/wine/blob/6d1b09405774c4f234ed3fa0088a9706deb7ad49/server/sock.c#L3973
	// https://github.com/wine-mirror/wine/blob/6d1b09405774c4f234ed3fa0088a9706deb7ad49/server/async.c#L280
	// We may cancel IO without closing the socket, i.e. TLS <1.3 socket sent a close_notify, which requires
	// a close_notify reply sent and strictly nothing else.
	// 
	// WSAESHUTDOWN can only mean shutdown() was called by us; we do that in graceful close.
	// Treat it as non-error, whatever is closing down is responsible for closure.
	//
	// In all these error codes, don't report as error.
	#define lwp_op_aborted(err) (err == ERROR_OPERATION_ABORTED || err == ERROR_HANDLES_CLOSED || err == WSAESHUTDOWN)
#else
	// In theory all cancelled ops in Linux will never trigger a reply; the handle closure will trigger
	// the event loops to discard any pending ops, and not trigger a callback for the discarded op in event pump.
	#define lwp_op_aborted(err) (err == EBADF)
#endif

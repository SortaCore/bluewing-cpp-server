/* vim: set noet ts=4 sw=4 sts=4 ft=c:
 *
 * Copyright (C) 2012 James McLaughlin.
 * Copyright (C) 2012-2022 Darkwire Software.
 * All rights reserved.
 *
 * liblacewing and Lacewing Relay/Blue source code are available under MIT license.
 * https://opensource.org/licenses/mit-license.php
*/

#ifndef _lw_fdstream_h
#define _lw_fdstream_h

#include "../stream.h"

struct _lw_fdstream
{
	struct _lw_stream stream;

	//lw_pump_watch watch;

	int fd;

	char flags;

	size_t size;
	size_t reading_size;
};

#define lwp_fdstream_flag_nagle		1
#define lwp_fdstream_flag_is_socket	2
#define lwp_fdstream_flag_autoclose	4
#define lwp_fdstream_flag_reading	 8

void lwp_fdstream_init (lw_fdstream, lw_pump);

#endif



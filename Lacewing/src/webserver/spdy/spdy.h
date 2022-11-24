/* vim: set noet ts=4 sw=4 sts=4 ft=c:
 *
 * Copyright (C) 2012 James McLaughlin.
 * Copyright (C) 2012-2022 Darkwire Software.
 * All rights reserved.
 *
 * liblacewing and Lacewing Relay/Blue source code are available under MIT license.
 * https://opensource.org/licenses/mit-license.php
*/

#include "../../../deps/spdy/include/spdy.h"

typedef struct lwp_ws_spdyclient
{
	struct _lwp_ws_client client;

	spdy_ctx * spdy;

	list (lw_ws_req, requests);

} * lwp_ws_spdyclient;

lwp_ws_client lwp_ws_spdyclient_new
	(lw_ws, lw_server_client socket, lw_bool secure, int version);

void lwp_ws_spdyclient_delete (lw_ws, lwp_ws_spdyclient);

extern const spdy_config lwp_ws_spdy_config;

extern const lw_streamdef def_spdyclient;
extern const lw_streamdef def_spdyrequest;


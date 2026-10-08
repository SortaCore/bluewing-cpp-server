/* vim: set noet ts=4 sw=4 sts=4 ft=c:
 *
 * Copyright (C) 2011, 2012, 2013 James McLaughlin et al.
 * Copyright (C) 2012-2026 Darkwire Software.
 * All rights reserved.
 *
 * liblacewing and Lacewing Relay/Blue source code are available under MIT license.
 * https://opensource.org/license/mit
*/

#include "../common.h"

struct _lw_thread
{
	lw_thread_proc proc;
	void * param, * result;
	char * name;

	pthread_t thread;
	lw_bool started;

	void * tag;
};

lw_thread lw_thread_new (const char * name, lw_thread_proc proc)
{
	lw_thread ctx = (lw_thread)calloc (sizeof (*ctx), 1);

	if (!ctx)
	  return 0;

	ctx->name = strdup (name);
	ctx->proc = proc;

	return ctx;
}

void lw_thread_delete (lw_thread ctx)
{
	if (!ctx)
	  return;

	lw_thread_join (ctx);

	free (ctx->name);
	free (ctx);
}

static void * thread_proc (void * ctxP)
{
	const lw_thread ctx = ctxP; // pthread entry point receives void *

	#ifdef HAVE_DECL_PR_SET_NAME
	  prctl (PR_SET_NAME, (unsigned long) ctx->name, 0, 0, 0);
	#endif

	ctx->result = ctx->proc(ctx->param);

	ctx->started = lw_false;

	return ctx->result;
}

void lw_thread_start (lw_thread ctx, void * param)
{
	if (lw_thread_started (ctx))
	  return;

	ctx->param = param;

	ctx->started = pthread_create(&ctx->thread, 0, thread_proc, ctx) == 0;
}

lw_bool lw_thread_started (lw_thread ctx)
{
	return ctx->started;
}

void * lw_thread_join (lw_thread ctx)
{
	if (!lw_thread_started (ctx))
	  return (void *) -1;

	void * exit_result;

	if (pthread_join (ctx->thread, &exit_result))
	  return (void *) -1;

	return exit_result;
}

void lw_thread_set_tag (lw_thread ctx, void * tag)
{
	ctx->tag = tag;
}

void * lw_thread_tag (lw_thread ctx)
{
	return ctx->tag;
}

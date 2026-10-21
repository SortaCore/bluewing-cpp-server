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
#include "pump.h"

lw_pump lw_pump_new (const lw_pumpdef * def)
{
	lw_pump ctx = (lw_pump) malloc (sizeof (*ctx) + def->tail_size);

	if (!ctx)
		return 0;

	lwp_pump_init (ctx, def);

	return ctx;
}

void lwp_pump_init (lw_pump ctx, const lw_pumpdef * def)
{
	memset (ctx, 0, sizeof (*ctx));

	ctx->def = def;
#ifdef ENABLE_THREADS
	ctx->thread_id = lw_thread_id_current();
#endif // ENABLE_THREADS
}

void * lw_pump_tail (lw_pump pump)
{
	return pump + 1;
}

lw_pump lw_pump_from_tail (void * tail)
{
	return ((lw_pump) tail) - 1;
}

void lw_pump_delete (lw_pump ctx)
{
	if (!ctx)
	  return;

	if (ctx->def->cleanup)
	  ctx->def->cleanup (ctx);

	free (ctx);
}

void lw_pump_add_user (lw_pump ctx)
{
	++ ctx->use_count;
}

void lw_pump_remove_user (lw_pump ctx)
{
	-- ctx->use_count;
}

lw_bool lw_pump_in_use (lw_pump ctx)
{
	return ctx->use_count > 0;
}

void lw_pump_post (lw_pump ctx, lw_pump_post_func proc, void * const param)
{
	ctx->def->post (ctx, proc, param);
}

#ifdef _WIN32

	lw_pump_watch lw_pump_add (lw_pump ctx, HANDLE handle, void * tag, lw_pump_callback callback)
	{
		const lw_pump_watch watch = ctx->def->add (ctx, handle, tag, callback);
		if (watch)
			lw_pump_add_user (ctx);
		return watch;
	}

	void lw_pump_update_callbacks (lw_pump ctx, lw_pump_watch watch, void * tag, lw_pump_callback callback)
	{
		ctx->def->update_callbacks (ctx, watch, tag, callback);
	}

#else

	lw_pump_watch lw_pump_add (lw_pump ctx, int fd, void * tag,
		lw_pump_callback on_read_ready, lw_pump_callback on_write_ready,
		lw_bool edge_triggered)
	{
		const lw_pump_watch watch = ctx->def->add (ctx, fd, tag,
			on_read_ready, on_write_ready, edge_triggered);
		if (watch)
			lw_pump_add_user (ctx);
		return watch;
	}

	void lw_pump_update_callbacks (lw_pump ctx, lw_pump_watch watch, void * tag,
		lw_pump_callback on_read_ready, lw_pump_callback on_write_ready,
		lw_bool edge_triggered)
	{
		ctx->def->update_callbacks (ctx, watch, tag,
			on_read_ready, on_write_ready, edge_triggered);
	}

#endif

void lw_pump_remove (lw_pump ctx, lw_pump_watch watch)
{
	if (watch == NULL)
		return;
	ctx->def->remove (ctx, watch);

	lw_pump_remove_user (ctx);
}

struct remove_proc_data
{
	lw_pump pump;
	lw_pump_watch watch;
};

static void * remove_proc (void * const data)
{
	lw_pump_remove (((struct remove_proc_data *)data)->pump, ((struct remove_proc_data*)data)->watch);

	free (data);
	return NULL;
}

void lw_pump_post_remove (lw_pump ctx, lw_pump_watch watch)
{
	struct remove_proc_data * const data =
	  (struct remove_proc_data *) lw_malloc_or_exit (sizeof (*data));

	data->pump = ctx;
	data->watch = watch;

	lw_pump_post (ctx, remove_proc, data);
}

void * lw_pump_tag (lw_pump ctx)
{
	return ctx->tag;
}

void lw_pump_set_tag (lw_pump ctx, void * tag)
{
	ctx->tag = tag;
}

void lw_pump_thread_check (lw_pump ctx)
{
	if (!lw_pump_is_thread(ctx))
	{
		always_log("Thread check failed\n");
		assert(!"Thread check failed");
	}
}

lw_bool lw_pump_is_thread (const struct _lw_pump * const ctx)
{
#ifdef ENABLE_THREADS
	return !ctx || lw_thread_id_equal(ctx->thread_id, lw_thread_id_current());
#else
	(void)ctx;
	return lw_true;
#endif
}

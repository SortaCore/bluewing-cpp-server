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
#include "eventpump.h"

enum
{
	sig_exit_eventloop,
	sig_remove,
	sig_post
};

#ifdef ENABLE_THREADS
	static void * lw_callback watcher (void *);
#endif

lw_eventpump lw_eventpump_new ()
{
	lw_eventpump ctx = (lw_eventpump)calloc (sizeof (*ctx), 1);

	if (!ctx)
	  return NULL;

	#ifdef ENABLE_THREADS
	  ctx->watcher.thread = lw_thread_new ("watcher", watcher);
	  ctx->watcher.resume_event = lw_event_new ();
	#endif

	lwp_pump_init (&ctx->pump, &def_eventpump);

	ctx->sync_signalparams = lw_sync_new ();

	int signalpipe [2];
	if (pipe(signalpipe) == -1)
	{
		ctx->signalpipe_read = ctx->signalpipe_write = -1;
		lw_pump_delete(&ctx->pump);
		return NULL;
	}

	ctx->signalpipe_read  = signalpipe [0];
	ctx->signalpipe_write = signalpipe [1];

	fcntl (ctx->signalpipe_read, F_SETFL,
		 fcntl (ctx->signalpipe_read, F_GETFL, 0) | O_NONBLOCK);

	ctx->queue = lwp_eventqueue_new ();

	lwp_eventqueue_add (ctx->queue, ctx->signalpipe_read,
						lw_true, lw_false, lw_true,
						NULL);

	return ctx;
}

static lw_bool process_event (lw_eventpump ctx, lwp_eventqueue_event event, lw_bool last_event)
{
	lw_bool keep_running = lw_true;
	lw_bool read_ready = lwp_eventqueue_event_read_ready (event),
			write_ready = lwp_eventqueue_event_write_ready (event);

	lw_pump_watch watch = (lw_pump_watch)lwp_eventqueue_event_tag (event);

	/* TODO: nothing kqueue specific belongs in this file, but since the
	* kqueue code doesn't actually look at the events it's the only place
	* we can put it.
	*/
	#ifdef USE_KQUEUE

		if (event.filter == EVFILT_TIMER)
		{
			lw_timer_force_tick ((lw_timer) event.udata);
			goto done;
		}

	#endif

	if (watch && watch->tag)
	{
		if (read_ready && watch->on_read_ready)
			watch->on_read_ready (watch->tag);

		if (write_ready && watch->on_write_ready)
			watch->on_write_ready (watch->tag);

		goto done;
	}

	/* A null tag means it must be the signal pipe */

	lw_sync_lock (ctx->sync_signalparams);

	for (;;) {
		char signal;

		const ssize_t amountRead = read(ctx->signalpipe_read, &signal, sizeof(signal));
		if (amountRead != 1)
		{
			if (amountRead == -1 && errno == EINTR)
				continue;
			if (amountRead == 0)
				always_log("signal pipe closed unexpectedly");
			else if (errno != EAGAIN)
				always_log("signal pipe read failed with error %d", errno);
			break;
		}

		switch (signal)
		{
		case sig_exit_eventloop:
		{
			lwp_trace("eventpump process_event: signal is exit eventloop.");
			lw_sync_release(ctx->sync_signalparams);
			// The caller stops dispatching this fetched array on exit.
			last_event = lw_true;
			keep_running = lw_false;
			goto done;
		}

		case sig_remove:
		{
			lwp_trace("eventpump process_event: signal is remove.");
			lw_pump_watch to_remove = (lw_pump_watch)list_front(void*, ctx->signalparams);
			list_pop_front(void*, ctx->signalparams);
			list_push(lw_pump_watch, ctx->closing_watches, to_remove);
			break;
		}

		case sig_post:
		{
			lwp_trace("eventpump process_event: signal is post.");
			void* func = list_front(void*, ctx->signalparams);
			list_pop_front(void*, ctx->signalparams);

			void* param = list_front(void*, ctx->signalparams);
			list_pop_front(void*, ctx->signalparams);

			// Release in case the function causes signal
			lw_sync_release (ctx->sync_signalparams);
			((void* (*) (void*)) func) (param);
			lw_sync_lock (ctx->sync_signalparams);
			break; // out of switch
		}
		};
	}

	lw_sync_release (ctx->sync_signalparams);

	done:
	// A later event in the fetched array may still name a removed watch.
	if (last_event)
	{
		list_each(lw_pump_watch, ctx->closing_watches, watch)
		{
			free(watch);
			lw_pump_remove_user((lw_pump)ctx);
		}
		list_clear(ctx->closing_watches);
	}
	return keep_running;
}

static void def_cleanup(lw_pump pump)
{
	lw_eventpump ctx = (lw_eventpump)pump;

	if (ctx->signalpipe_read != -1)
	{
		// Drain deferred removals and posts, including any queued by their callbacks;
		// an entirely empty event has null function pointers, but will continue
		// past to cause the pump signal pipe to be emptied.
		lwp_eventqueue_event clear = { 0 };
		
		while (!process_event(ctx, clear, lw_true))
			;

		close(ctx->signalpipe_read);
		close(ctx->signalpipe_write);
	}

	lwp_eventqueue_update(ctx->queue, ctx->signalpipe_read,
		lw_true, lw_false, lw_false, lw_false, lw_true, lw_false, NULL, NULL);

#ifdef ENABLE_THREADS
	if (lw_thread_started(ctx->watcher.thread))
	{
		lw_event_signal(ctx->watcher.resume_event);
		lw_thread_join(ctx->watcher.thread);
	}
	lw_thread_delete(ctx->watcher.thread);
	lw_sync_delete(ctx->sync_signalparams);

	lw_event_delete(ctx->watcher.resume_event);
#endif

	list_clear(ctx->signalparams);
	lwp_eventqueue_delete(ctx->queue);
	ctx->queue = (lwp_eventqueue)~0;
}

lw_error lw_eventpump_tick (lw_eventpump ctx)
{
	lw_bool need_watcher_resume = lw_false;

	#ifdef ENABLE_THREADS

		if (ctx->watcher.num_events > 0)
		{
			/* sleepy ticking: the watcher thread already grabbed some events we
			* need to process.
			*/
			for (int i = 0; i < ctx->watcher.num_events; ++i)
			{
				if (!process_event(ctx, ctx->watcher.events[i], i == ctx->watcher.num_events - 1))
				{
					ctx->watcher.num_events = 0;
					need_watcher_resume = lw_true;
					goto finish_tick;
				}
			}

			ctx->watcher.num_events = 0;

			need_watcher_resume = lw_true;
		}

	#endif

	lwp_eventqueue_event events [max_events];

	int count = lwp_eventqueue_drain (ctx->queue, lw_false, max_events, events);

	for (int i = 0; i < count; ++ i)
		if (!process_event(ctx, events[i], i == count - 1))
			break;

	finish_tick:
	#ifdef ENABLE_THREADS
		if (need_watcher_resume)
			lw_event_signal (ctx->watcher.resume_event);
	#endif

	return 0;
}

lw_error lw_eventpump_start_eventloop (lw_eventpump ctx)
{
	int do_loop = 1;

	while (do_loop)
	{
	  lwp_eventqueue_event events [max_events];

	  int count = lwp_eventqueue_drain (ctx->queue, lw_true, max_events, events);

	  if (count == -1)
	  {
		 if (errno == EINTR)
			continue;

		 always_log ("epoll error: %d", errno);
		 break;
	  }

	  for (int i = 0; i < count; ++ i)
	  {
		 if (!process_event(ctx, events[i], i == count - 1))
		 {
			do_loop = 0;
			break;
		 }
	  }
	}

	return 0;
}

void lw_eventpump_post_eventloop_exit (lw_eventpump ctx)
{
	// Each post/remove writes one byte. Filling the pipe generally takes thousands
	// of undrained events (often about 64K on Linux); capacity varies by OS.
	// If it fills, this write blocks until the pump drains it.
	char signal = sig_exit_eventloop;
	if (write(ctx->signalpipe_write, &signal, sizeof(signal)) == -1)
		always_log ("pipe failed to write with error %d.", errno);
}

lw_error lw_eventpump_start_sleepy_ticking
	(lw_eventpump ctx, void (lw_callback * on_tick_needed) (lw_eventpump))
{
	#ifdef ENABLE_THREADS
		ctx->on_tick_needed = on_tick_needed;
		lw_thread_start (ctx->watcher.thread, ctx);
	#else
		/* TODO error */
	#endif

	return 0;
}

#ifdef ENABLE_THREADS

static void * lw_callback watcher (void * data)
{
	lw_eventpump ctx = (lw_eventpump)data;
	for (;;)
	{
		assert (ctx->watcher.num_events == 0);

		int count = lwp_eventqueue_drain (ctx->queue,
			lw_true, max_events, ctx->watcher.events);

		if (count == -1)
		{
			if (errno == EINTR)
				continue;

			always_log ("drain error: %d", errno);
			break;
		}

		if (count == 0)
			continue;

		ctx->watcher.num_events = count;

		/*	We have some events. Notify the application from this thread, then
			wait for tick() to be called from the application main thread. */
		ctx->on_tick_needed (ctx);

		lw_event_wait (ctx->watcher.resume_event, -1);
		lw_event_unsignal (ctx->watcher.resume_event);
	}
	return NULL;
}

#endif

static lw_pump_watch def_add (lw_pump pump, int fd, void * tag,
							  lw_pump_callback on_read_ready,
							  lw_pump_callback on_write_ready,
							  lw_bool edge_triggered)
{
	lw_eventpump ctx = (lw_eventpump) pump;

	if ((!on_read_ready) && (!on_write_ready))
		return 0;

	lw_pump_watch watch = (lw_pump_watch)calloc (sizeof (*watch), 1);

	if (!watch)
		return 0;

	watch->fd = fd;
	watch->on_read_ready = on_read_ready;
	watch->on_write_ready = on_write_ready;
	watch->edge_triggered = edge_triggered;
	watch->tag = tag;
	lwp_trace("def_add calling lwp_eventqueue_add: fd %d; watch %p, tag %p, on_read_ready set to %p, on_write_ready set to %p.", fd, (void *)watch, watch->tag,
		(void *)on_read_ready, (void *)on_write_ready);

	lwp_eventqueue_add (ctx->queue,
						fd,
						on_read_ready != NULL,
						on_write_ready != NULL,
						edge_triggered,
						watch);

	lw_pump_add_user ((lw_pump) ctx);

	return watch;
}

lw_bool global_delete_block = lw_false;

static void def_update_callbacks (lw_pump pump,
								  lw_pump_watch watch, void * tag,
								  lw_pump_callback on_read_ready,
								  lw_pump_callback on_write_ready,
								  lw_bool edge_triggered)
{
	lw_eventpump ctx = (lw_eventpump) pump;

	if ( ((on_read_ready != 0) != (watch->on_read_ready != 0))
		 || ((on_write_ready != 0) != (watch->on_write_ready != 0))
		 || (edge_triggered != watch->edge_triggered)
		 || tag != watch->tag)
	{
	  lwp_eventqueue_update (ctx->queue,
							 watch->fd,
							 watch->on_read_ready != NULL, on_read_ready != NULL,
							 watch->on_write_ready != NULL, on_write_ready != NULL,
							 watch->edge_triggered, edge_triggered,
							 watch, watch);
	}

	watch->on_read_ready = on_read_ready;
	watch->on_write_ready = on_write_ready;
	watch->edge_triggered = edge_triggered;
	watch->tag = tag;
}

static void def_remove (lw_pump pump, lw_pump_watch watch)
{
	lw_eventpump ctx = (lw_eventpump) pump;

	/*
		James note: Should this remove the FD from the eventqueue immediately?
		LK response: no, "when you close the FD it is automatically removed from all epoll/select lists"
		Phi test: Actually, this falls over very quickly if you don't.
	*/

	lwp_eventqueue_update(ctx->queue, watch->fd,
		watch->on_read_ready != NULL, lw_false,
		watch->on_write_ready != NULL, lw_false,
		watch->edge_triggered, watch->edge_triggered, watch->tag, watch->tag);
	watch->on_read_ready = NULL;
	watch->on_write_ready = NULL;

	// The signal retires the watch; the last fetched event frees it.
	lw_sync_lock (ctx->sync_signalparams);

		list_push (void *, ctx->signalparams, watch);

		char signal = sig_remove;
		if (write(ctx->signalpipe_write, &signal, sizeof(signal)) == -1)
			always_log("pipe failed to write with error %d.", errno);

	lw_sync_release (ctx->sync_signalparams);
}

static void def_post (lw_pump pump, const lw_pump_post_func func, void * param)
{
	lw_eventpump ctx = (lw_eventpump) pump;

	lw_sync_lock (ctx->sync_signalparams);

		_Static_assert(sizeof(lw_pump_post_func) == sizeof(void*), "Function pointer and regular pointer diff");

		list_push (void *, ctx->signalparams, func);
		list_push (void *, ctx->signalparams, param);

		char signal = sig_post;
		if (write(ctx->signalpipe_write, &signal, sizeof(signal)) == -1)
			always_log("pipe failed to write with error %d.", errno);

	lw_sync_release (ctx->sync_signalparams);
}

const lw_pumpdef def_eventpump =
{
	.add				= def_add,
	.update_callbacks	= def_update_callbacks,
	.remove				= def_remove,
	.post				= def_post,
	.cleanup			= def_cleanup
};

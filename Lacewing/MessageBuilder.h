/* vim: set noet ts=4 sw=4 sts=4 ft=cpp:
 *
 * Copyright (C) 2011 James McLaughlin.
 * Copyright (C) 2012-2026 Darkwire Software.
 * All rights reserved.
 *
 * liblacewing and Lacewing Relay/Blue source code are available under MIT license.
 * https://opensource.org/license/mit
*/

#include "Lacewing.h"
#include "src/refcount.h"
#include <vector>
#include <assert.h>

#ifndef LacewingMessageBuilder
#define LacewingMessageBuilder

class messagebuilder
{

protected:

	lw_ui32 allocated = 0;
	lacewing::pump pump;
	// If true, writes are on pump thread, can be done sync
	lw_bool use_async_write;

	void lacewing_tcp_write(lw_stream stream, const char* data, size_t size) const;

public:

	lw_ui8 * buffer = nullptr;
	lw_ui32 size = 0U;
	std::thread::id threadOwner;

	messagebuilder() = delete;
	messagebuilder(const messagebuilder&) = delete;

	messagebuilder(lacewing::pump pmp) : pump(pmp)
	{
		updatethreadowner();
	}

	void updatethreadowner()
	{
		threadOwner = std::this_thread::get_id();
		use_async_write = !lw_pump_is_thread((lw_pump)pump);
	}

	~ messagebuilder()
	{
		free(buffer);
		buffer = nullptr;
	}

	void add(const char * const bufferParam, size_t sizeParam)
	{
		if (sizeParam == SIZE_MAX)
			sizeParam = (lw_ui32)strlen(bufferParam);

		if constexpr (sizeof(sizeParam) > 4)
			assert(sizeParam < 0xFFFFFFFF);

		const lw_ui32 sizeLocal = (lw_ui32)sizeParam;

		if (this->size + sizeLocal > allocated)
		{
			const int origalloc = allocated;
			if (!allocated)
				allocated = 1024 * 4;
			else
				allocated *= 3;

			if (this->size + sizeLocal > allocated)
				allocated += sizeLocal;

			this->buffer = (lw_ui8 *)lw_realloc_or_exit(this->buffer, allocated);
			memset(this->buffer + origalloc, 0, allocated - origalloc);
		}

		memcpy(this->buffer + this->size, bufferParam, sizeLocal);
		this->size += sizeLocal;
	}

	template<typename t>
	inline void add (t value)
	{
		// If this second assertion triggers, you're passing a pointer value to be embedded in the message.
		// This will append the address the pointer points to, NOT the content of the pointer.
		// Since this is unlikely to be expected behaviour, you should check your code.
		// You probably want the add(data, sizeof(data))
		// If adding a string, pass add(data, -1)
		// If adding a single byte, pass add(&data, 1)
		static_assert(!std::is_pointer<t>::value,
			"Check you meant to pass a pointer address. That doesn't make a lot of sense.");
		// std::string is nasty
		static_assert(!std::is_same<t, std::string>::value,
			"std::string data type being added.");
		static_assert(std::is_integral<t>::value,
			"Advanced data type being added.");

		add((const char *) &value, sizeof(t));
	}

	/*
	inline void AddNetwork16Bit (short Value)
	{
		Value = htons (Value);
		Add ((char *) &Value, sizeof(Value));
	}

	inline void AddNetwork24Bit (int Value)
	{
		Value = htonl (Value);
		Add (((char *) &Value) + 1, 3);
	}

	inline void AddNetwork32Bit (int Value)
	{
		Value = htonl (Value);
		Add ((char *) &Value, sizeof(Value));
	}

	inline void AddNetworkX31Bit (unsigned int Value)
	{
		Value = htonl (Value);

		*(char *) &Value &= 0x7F; // 0 first bit

		Add ((char *) &Value, sizeof(Value));
	}*/

	void reset()
	{
		size = 0;
	}

	void send(lacewing::stream socket, int offset = 0)
	{
		lacewing_tcp_write((lw_stream)socket, (char *)buffer + offset, size - offset);
	}

	void send(lacewing::udp udp, lacewing::address from, lw_ui32 ifidx, lacewing::address to, int offset = 0)
	{
		udp->send(from, ifidx, to, (char *)buffer + offset, size - offset);
	}

};
template<> inline
void messagebuilder::add(std::string value)
{
	add(value.data(), (lw_i32)value.size());
}
template<> inline
void messagebuilder::add(std::string_view value)
{
	add(value.data(), (lw_i32)value.size());
}

inline void messagebuilder::lacewing_tcp_write(lw_stream stream, const char* data, size_t size) const
{
	assert(stream);

	if (!size)
		return;

	if (!use_async_write)
	{
		lw_stream_write(stream, data, size);
		return;
	}

	struct async_write_post_param
	{
		lw_stream stream;
		std::string data;
	};

	const auto async_write_post_func = [](void* postP) -> void *
	{
		const std::unique_ptr<async_write_post_param> post((async_write_post_param*)postP);

		lw_stream_write(post->stream, post->data.data(), post->data.size());
		lwp_release(post->stream, "relay TCP write post");
		return nullptr;
	};
	const auto post = new async_write_post_param { stream, std::string(data, size) };
	lwp_retain(stream, "relay TCP write post");
	pump->post(async_write_post_func, post);
}


#endif

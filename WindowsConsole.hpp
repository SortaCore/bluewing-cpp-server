#pragma once

// If the user hasn't specified a target Windows version via _WIN32_WINNT, and is using an _xp toolset (indicated by _USING_V110_SDK71_),
// then _WIN32_WINNT will be set to Windows XP (0x0501).
#if !defined(_WIN32_WINNT) && defined(_USING_V110_SDK71_)
#	define _WIN32_WINNT _WIN32_WINNT_WINXP
#	define WINVER		_WIN32_WINNT_WINXP
#endif

// Disables unused Windows tech and preprocessor macros from headers
#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

// For icon file
#include "resource.h"

// For memory leak finding
#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

// Fix some UTF-16 issues. Adapted from https://stackoverflow.com/a/48180107 .
#ifndef MS_STDLIB_BUGS
#  if ( _MSC_VER || __MINGW32__ || __MSVCRT__ )
#    define MS_STDLIB_BUGS 1
#  else
#    define MS_STDLIB_BUGS 0
#  endif
#endif

#if MS_STDLIB_BUGS
#	include <io.h>
#	include <fcntl.h>
#	include <iostream>
#endif
#include <iomanip>

void init_locale()
{
	// Constant for fwide().
	constexpr int wide_oriented = 1;

#if MS_STDLIB_BUGS
	static const char locale_name[] = ".1200";
	// std::cout will now create app-stopping error if used, only std::wcout is allowed
	fflush(stdout);
	_setmode(_fileno(stdout), _O_WTEXT);
	fflush(stderr);
	_setmode(_fileno(stderr), _O_WTEXT);
#else
	// The correct locale name may vary by OS, e.g., "en_US.utf8".
	static const char locale_name[] = "";
#endif

	std::cout.imbue(std::locale(std::string()));
	setlocale(LC_ALL, locale_name);
	fwide(stdout, wide_oriented);
}
#include "GenericConsole.hpp"

// UTF-8 text to wchar_t text, for Windows
std::wstring UTF8ToWide(const std::string_view str)
{
	wchar_t* wide = lw_char_to_wchar(str.data(), (int)str.size());
	if (!wide)
		return std::wstring();
	const std::wstring wideStr = wide;
	free(wide);
	return wideStr;
}
std::string WideToUTF8(const std::wstring_view wStr)
{
	if (wStr.empty())
		return std::string();
	std::string u8Str;
	BOOL failed;
	int length = WideCharToMultiByte(CP_UTF8, 0, wStr.data(), (int)wStr.size(), NULL, 0, NULL, &failed);
	if (length > 0 && !failed)
	{
		u8Str.resize(length + 1); // zero-alloc
		length = WideCharToMultiByte(CP_UTF8, 0, wStr.data(), (int)wStr.size(), u8Str.data(), (int)u8Str.size(), NULL, &failed);
		u8Str.resize(length);
	}
	if (length < 0 || failed)
		u8Str = "(Error converting UTF-16 to UTF_8)"s;
	return u8Str;
}

// These original console variables are all invalid if isConsoleInput is false
DWORD conOrigInputMode, conOrigOutputMode;
WORD conOrigTextAttributes;
CONSOLE_CURSOR_INFO conOrigCursorInfo;
HICON conSmallIcon, conBigIcon, conOrigSmallIcon, conOrigBigIcon;
HWND consoleWin;
HANDLE hStdOut, hStdIn;

// Lacewing uses a sync inside lw_trace, which is singleton and never freed.
// lw_trace() is a no-op if _lacewing_debug isn't defined.
// To let garbage collector not see it as a leak:
#if defined(_CRTDBG_MAP_ALLOC) && defined(_lacewing_debug)
extern "C" { extern _lw_sync* lw_trace_sync; }
#endif

// Handler called by OS that spawns a thread in this process for Close, Ctrl-C and Ctrl-Break events.
// Once close responds, the app is killed.
BOOL WINAPI CloseHandler(DWORD ctrlType);
#define UTF8Windows

// For _gettch()
#include <tchar.h>
#include <conio.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef DISABLE_NEWLINE_AUTO_RETURN
#define DISABLE_NEWLINE_AUTO_RETURN 0x0008
#endif

// In Windows, string case-insensitive comparison is _stricmp(), everywhere else is strcasecmp()
#define strcasecmp(a, b) _tcsicmp(a, b)
// POSIX complaint
#define kbhit() _kbhit()

#pragma once
#include <iostream>

#ifdef _WIN32
#include <windows.h>
static HANDLE hStdout;
#endif

template<class _Elem, class _Traits>
inline std::basic_ostream<_Elem, _Traits> & blue(std::basic_ostream<_Elem, _Traits> &s)
{
#ifdef _WIN32
	SetConsoleTextAttribute(hStdout, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
#else
	s << "\033[94m";
#endif
	return s;
}

template<class _Elem, class _Traits>
inline std::basic_ostream<_Elem, _Traits> & red(std::basic_ostream<_Elem, _Traits> & s)
{
#ifdef _WIN32
	SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_INTENSITY);
#else
	s << "\033[91m";
#endif
	return s;
}

template<class _Elem, class _Traits>
inline std::basic_ostream<_Elem, _Traits> & green(std::basic_ostream<_Elem, _Traits> & s)
{
#ifdef _WIN32
	SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
#else
	s << "\033[92m";
#endif
	return s;
}

template<class _Elem, class _Traits>
inline std::basic_ostream<_Elem, _Traits> & yellow(std::basic_ostream<_Elem, _Traits> & s)
{
#ifdef _WIN32
	SetConsoleTextAttribute(hStdout, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);
#else
	s << "\033[93m";
#endif
	return s;
}

template <class _Elem, class _Traits>
inline std::basic_ostream<_Elem, _Traits> & white(std::basic_ostream<_Elem, _Traits> & s)
{
#ifdef _WIN32
	SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
#else
	s << "\033[37m";
#endif
	return s;
}

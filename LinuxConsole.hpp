#pragma once

#include <sys/stat.h>   // for stat ()
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/cdefs.h>
// For cap_get_proc(), allows checking for raw socket and low port number binds; requires libcap-dev
#if __has_include(<sys/capability.h>)
#	include <sys/capability.h>
#endif // __has_include
#include <pwd.h>
#include <signal.h> // for SIGINT etc
#if __has_include(<conio.h>)
#include <conio.h>
#endif

// Handles user and OS interrupts, e.g. Ctrl-C, OS shutdown/quit signal, etc.
void CloseHandler(int sig);

// Used for terminal settings when a terminal is present.
// Has a lifetime bigger than the app, so it must be restored on app exit.
struct termios origTerminalSettings;

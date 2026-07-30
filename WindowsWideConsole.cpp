/* vim: set noet ts=4 sw=4 sts=4 ft=cpp:
 *
 * Created by Darkwire Software.
 *
 * This example server file is available unlicensed; the MIT license of liblacewing/Lacewing Relay does not apply to this file.
 *
 * This file is used as a template to make OS-specific code. Several preprocessor-level things are parsed and removed here.
 * You should not modify this template unless you are writing code for all platforms.
*/

// Includes OS-specific headers
#include "WindowsConsole.hpp"

// Includes all global variables and headers that both Windows wchar_t and non-Windows char use.
#include "GenericConsole.hpp"

// Reprints the time and statistics line. Called by lineEnd() and when stats timer ticks.
static void ReprintStatisticsLine()
{
	// We don't maintain a stats line if we're not writing to a console.
	// We also should not print if the server is pre-startup or currently shutting down.
	if (!isConsoleOutput || lastTimeAndStats.empty())
		return;

	std::wcout << gray << lastTimeAndStats << std::flush;
}

// Pads the last output line and inserts newline, appending either just time prefix to next line,
// or reprinting whole statistics line
// @param reprintStatsLine if true, prints the statistics line again; if false, prints time only,
//						   expecting another line written immediately by caller
template <class _Elem, class _Traits>
static std::basic_ostream<_Elem, _Traits> & operator << (std::basic_ostream<_Elem, _Traits>& str, const lineEndProp & wrp)
{
	// If we're not outputting to console, we don't want to pad or recolor, just output time
	if (!isConsoleOutput)
	{
		std::wcout << L'\n';
		if (!wrp.reprintStatsLine)
			std::wcout << timeBuffer;
		return str;
	}
		
	CONSOLE_SCREEN_BUFFER_INFO csbi = {};
	if (GetConsoleScreenBufferInfo(hStdOut, &csbi))
	{
		// If we wrote a line that's shorter than last statistics line, we clear whatever wasn't overwritten
		// from end of last wrote line (cursor x) to end of console via padding an empty string.
		const int charsToFill = csbi.dwSize.X - csbi.dwCursorPosition.X;
		assert(charsToFill >= 0);
		std::wcout << std::setw((std::streamsize)charsToFill) << L""sv << std::setw(0);
	}
	std::wcout << L'\n';

	if (wrp.reprintStatsLine)
		ReprintStatisticsLine();
	else // prepare for another line
		std::wcout << timeBuffer;
	return str;
}

// Checks if a port text input by a user is valid or re-used elsewhere.
static void CheckPort(const lw_char * portStr, lw_ui16 * writeTo, std::function<void()> errInv)
{
	const std::uint32_t portNum = static_cast<std::uint32_t>(std::wcstoul(portStr, nullptr, 10));

	// Check port is in valid range. Port 843 is used for Flash policy.
	if (portNum == 843 || portNum == 0 || portNum > std::numeric_limits<lw_ui16>::max())
	{
		std::wcout << red;
		errInv();
		std::wcout << L" had invalid port number "sv << portStr << L'.' << lineEnd();
		return;
	}
	*writeTo = (lw_ui16)portNum;

	// Check port does not match others
	if ((writeTo != &mainPort && *writeTo == mainPort) ||
		(writeTo != &websocketNonSecurePort && *writeTo == websocketNonSecurePort) ||
		(writeTo != &websocketSecurePort && *writeTo == websocketSecurePort))
	{
		errInv();
		std::wcout << L" port number "sv << portStr << L" was reused in several ports."sv << lineEnd();
	}
}
static lw_string GetConsoleLine(bool password = false)
{
	assert(isConsoleOutput);

	// Due to outputting to file, running under debugger, or other reasons, we don't prompt user
	if (!requestUserInput)
	{
#ifdef _DEBUG
		std::wcout << L"(prompting disabled)\n"sv;
#endif
		return lw_string();
	}

	// Set console color for user's response text
	std::wcout << userresponsecolor;

	// Turn off echo of input to output
	DWORD conMode;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(hStdOut, &csbi);
	if (password &&
		(!GetConsoleMode(hStdOut, &conMode) || !SetConsoleMode(hStdOut, conMode & ~ENABLE_ECHO_INPUT)))
	{
		std::abort();
	}

	lw_string consoleInputLine;
	std::getline(std::wcin, consoleInputLine);

	// User aborted reading input e.g. Ctrl-C
	if (shutdowned || std::wcin.fail())
		return lw_string();

	// restore cursor pos to previous line if no input to show
	if (consoleInputLine.empty())
		SetConsoleCursorPosition(hStdOut, csbi.dwCursorPosition);

	// restore echo and generate random asterisk for password
	if (password)
	{
		SetConsoleMode(hStdOut, conMode);
		SetConsoleCursorPosition(hStdOut, csbi.dwCursorPosition);
		std::wcout << lw_string(consoleInputLine.empty() ? 10 + (rand() % 20) : consoleInputLine.size(), L'*') << L'\n';
	}
	else if (consoleInputLine.empty())
		std::wcout << L"(empty input)\n"sv;
	return consoleInputLine;
}
// Looks for matching default TLS cert files and uses the first to match
static void GuessCertPath()
{
	if (!wsFullChainPath.empty())
		return;

	// Search app directory for matching files
	// Windows: PFX file that should have both private and public key
	if (lw_file_exists("./tlscert.pfx"))
	{
		wsPrivKeyPath = wsFullChainPath = "./tlscert.pfx"s;
		std::wcout << green << L"Auto-set cert file to tlscert.pfx from current directory."sv << lineEnd();
		return;
	}
	if (lw_file_exists("./fullchain.pem") && lw_file_exists("./privkey.pem"))
	{
		wsPrivKeyPath = "./privkey.pem"s;
		wsFullChainPath = "./fullchain.pem"s;
		std::wcout << green << L"Auto-set cert files to privkey.pem and fullchain.pem from current directory."sv << lineEnd();
		return;
	}
	// Not found at all - if websocket insecure was on, they probably want a secure cert
	if (websocketNonSecurePort)
	{
		std::wcout << yellow << L"Couldn't auto-find TLS certficate files - expecting "sv;
		std::wcout << L"either \"tlscert.pfx\" OR "sv;
		std::wcout << L"\"fullchain.pem\" and \"privkey.pem\" in app folder."sv << lineEnd();
	}
}
static bool GetPortFromInput(const lw_string_view req, lw_ui16 * writeTo, bool requireCert, lw_ui16 defaultVal)
{
	// Assume defaults will be fine if not prompting for settings
	if (!requestUserInput && !requireCert)
	{
		*writeTo = defaultVal;
		return true;
	}

	// User already aborted reading input
	if (shutdowned || (requestUserInput && std::wcin.fail()))
		return false;

	lw_string consoleInputLine;
	if (requestUserInput && !requireCert)
		std::wcout << userpromptcolor << L"Enter a "sv << req << L" port (leave empty for default " << defaultVal << L"):\n"sv;
	// else cert is required for this port: guess cert
	else
	{
		GuessCertPath();

		if (!requestUserInput)
		{
			*writeTo = defaultVal;
			return true;
		}
		std::wcout << userpromptcolor << L"Enter a "sv << req << L" port (leave empty for default "sv << defaultVal <<
			L", or pass 0 to disable secure websocket):\n"sv;
	}
	consoleInputLine = GetConsoleLine();

	bool good = true;
	if (consoleInputLine.empty())
	{
		// User pressed Ctrl-C during input
		if (shutdowned || std::wcin.fail())
			return false;

		*writeTo = defaultVal;
	}
	else
	{
		CheckPort(consoleInputLine.c_str(), writeTo, [&]() {
			std::wcout << L"Invalid input: "sv << req;
			good = false;
		});
	}
	// Cert is required for this port, and we don't have cmdline arg
	if (good && requireCert && *writeTo != 0)
	{
		if (wsFullChainPath.empty())
		{
			std::wcout << userpromptcolor << L"Enter a path to TLS certificate file (combined PFX or full chain PEM), or leave empty to disable websocket secure hosting:\n"sv;
			consoleInputLine = GetConsoleLine();
			if (consoleInputLine.empty())
			{
				std::wcout << green << L"Left empty. Will continue webserver with just insecure websocket."sv << lineEnd();
				websocketSecurePort = 0;
				return true;
			}
			wsFullChainPath = WideToUTF8(consoleInputLine);
		}
		if (wsPrivKeyPath.empty())
		{
			std::wcout << userpromptcolor << L"Enter a path to SSL priv key certificate file (PFX or PEM), or leave empty if part of chain file:\n"sv;
			consoleInputLine = GetConsoleLine();
			wsPrivKeyPath = consoleInputLine.empty() ? wsFullChainPath : WideToUTF8(consoleInputLine);
		}

		if (wsPassPhrase.empty())
		{
			std::wcout << userpromptcolor << L"Enter a password to the certificate file(s), or leave empty if none:\n"sv;
			consoleInputLine = GetConsoleLine(true);
			wsPassPhrase = WideToUTF8(consoleInputLine);
		}
	}

	return good;
}

// Converts time_t to full date-time representation based on local date format
lw_string fulltimetostring(std::time_t timepoint)
{
	lw_string buffer(100, L'\0');
	std::tm timeinfo = { 0 };
	if (!localtime_s(&timeinfo, &timepoint))
		std::_tcsftime(buffer.data(), buffer.size(), L"%I:%M:%S%p %x", &timeinfo);
	buffer.resize(buffer.find(L'\0'));
	return buffer;
}

/** Prints total statistics, mid-app or at end of app.
 * @param endOfApp If true, program is at end; current time is referred to as end time.
 * @remarks Does not print user list, ban list, IP list. Those are only accessible via admin commands.
 *			If such a thing is widely needed, the console app needs to import ncurses or something so that it can
 *			have on-console subwindows.
*/
static void PrintTotalStatistics(const bool endOfApp)
{
	std::wcout << green << std::setw(70) << std::setfill(L'=') << L""sv << std::setw(0) << std::setfill(L' ') << lineEnd(false);
	if (endOfApp)
		std::wcout << L"Program completed. Total statistics:"sv << lineEnd(false);
	else
		std::wcout << L"Manual statistics request. Statistics since start of server:" << lineEnd(false);
	
	const std::time_t curTime = time(NULL);
	const std::uint64_t secondsUp = std::max<std::uint64_t>(1, (std::uint64_t)std::ceil(difftime(curTime, startTime)));
	// Division is floor by default
	const std::uint64_t hours = secondsUp / (60ULL * 60ULL), minutes = (secondsUp / 60ULL) % 60ULL, seconds = secondsUp % 60ULL;
	std::wcout
		<< L"     Start time: "sv << fulltimetostring(startTime) << L". "sv << lineEnd(false)
		<< (endOfApp ? L"       End"sv : L"   Current"sv) << L" time: "sv << fulltimetostring(curTime) << L". "sv << lineEnd(false)
		<< L"    Hosting for: "sv << hours << L" hrs, "sv << minutes << L" mins, "sv << seconds << L" seconds ("sv << secondsUp << L" seconds total)."sv << lineEnd(false)
		<< L"   Max in 1 sec: "sv << serverstats.in.highestSec.bytes << L" bytes in, "sv << serverstats.out.highestSec.bytes << L" bytes out."sv << lineEnd(false)
		<< L"                 "sv << serverstats.in.highestSec.msg << L" msgs in, "sv << serverstats.out.highestSec.msg << L" msgs out (may be diff seconds)."sv << lineEnd(false)
		<< L"    Avg per sec: "sv << (serverstats.in.total.bytes / secondsUp) << L" bytes in, "sv << (serverstats.out.total.bytes / secondsUp) << L" bytes out."sv << lineEnd(false)
		<< L"                 "sv << (serverstats.in.total.msg / secondsUp) << L" msgs in, "sv << (serverstats.out.total.msg / secondsUp) << L" msgs out."sv << lineEnd(false)
		<< L"          Total: "sv << serverstats.in.total.bytes << L" bytes in, "sv << serverstats.out.total.bytes << L" bytes out."sv << lineEnd(false)
		<< L"                 "sv << serverstats.in.total.msg << L" msgs in, "sv << serverstats.out.total.msg << L" msgs out."sv << lineEnd(false)
		<< L"    Max clients: "sv << serverstats.maxClients << L", max channels: "sv << serverstats.maxChannels << L'.' << lineEnd(false);
	if (endOfApp)
		std::wcout << L"Current clients: "sv << globalserver->clientcount() << L", current channels: "sv << globalserver->channelcount() << L'.' << lineEnd(false);
	std::wcout
		<< std::setw(70) << std::setfill(L'=') << L""sv << std::setw(0) << std::setfill(L' ') << lineEnd(!endOfApp);
}

/**
 * @brief Entry point for the program, where OS starts this program up
 * @param argc Number of entries in argv
 * @param argv Null-terminated arguments, the first usually the program's full path
 *			   Running "app.exe -thing val" will result in argc = 3, with argv being
 *			   [0] = "...app.exe", [1] = "-thing", [2] = "val"
 * @return 0 for success, -1 for error; usually negative is for errors, positive for info,
 *		   but by spec any non-zero is error.
 * @remarks Although OSes don't tend to react to error code, you can read it after app exit,
 *			e.g. in batch via %ERRORLEVEL%, bash via $?, and so on.
*/
int wmain(const int argcf, lw_char* argv[])
{
	const std::size_t argc = static_cast<std::size_t>(argcf);
	// If true, cmdline is set to require admin
	bool requireAdmin = false;
	
#ifdef _DEBUG
	// Enable memory tracking (does nothing in Release)
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	// If running in debugger, clear the console window
	if (IsDebuggerPresent())
		system("cls");
#endif // _DEBUG

	// UTF-8 console requires Windows 10, 1903+

	// Handle closing nicely - Ctrl-C, Ctrl-Break, and pressing the X on console window.
	// Registering no handler will result in default behavior, which normally means OS will instantly terminate app.
	//
	// This is another entry point from OS -> program; OS will start up a thread in this app to call CloseHandler.
	// Note that returning from some handlers will lead OS to instantly terminate app anyway,
	// as some handlers are more for OS notifying a program to quit, rather than a user notification.
	if (!SetConsoleCtrlHandler(CloseHandler, TRUE))
	{
		std::wcout << L"Could not set console close handler, error "sv << GetLastError() << L".\n"sv;
		return ENOTSUP;
	}

#ifndef _DEBUG
	// We don't use C-style printf(), so desync C++ console output (std::wcout) and C (printf, puts).
	// It's unclear whether std::wcout or printf is faster; and some say std::wcout is faster
	// only with a fast locale.
	// Since Bluewing currently requires C++17, for use of std::string_view and std::shared_ptr,
	// we'll stick to C++ console.
	std::ios_base::sync_with_stdio(false);
#endif // !_DEBUG

	// For Unicode text format
	init_locale();

	// Get access to console
	hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	hStdIn = GetStdHandle(STD_INPUT_HANDLE);

	// If running under debugger, we may not care to ask for settings
	if (IsDebuggerPresent())
		requestUserInput = requestUserInputUnderDebugger;

	// Update timeBuffer for startup output
	OnTimerTick(nullptr);

	// Get app directory that app is running from, by getting running app full path.
	// argv[0] may contain relative path, so it shouldn't be relied on.
	{
		lw_string filenameBuf;
#ifdef _MSC_VER
		// MSVC provide a shortcut to get current running app path, but not all compilers have it.
		TCHAR* filePath = NULL;
		if (_get_tpgmptr(&filePath) == 0)
			filenameBuf = filePath;
#endif // _MSC_VER
		DWORD pathLen;
		// Fall back on manual lookup of EXE path
		if (filenameBuf.empty())
		{
			// We can't get path size via passing null, so we have to repeat with increasing buffer
			filenameBuf.resize(1024);
			while (true)
			{
				// Get full path of EXE, including EXE filename + ext.
				pathLen = GetModuleFileName(NULL, filenameBuf.data(), (DWORD)filenameBuf.size());
				if (pathLen == 0)
				{
					// Extend the buffer to next power of 2
					if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
					{
						filenameBuf.resize(filenameBuf.size() << 1);
						continue;
					}

					// Some other error, give up
					std::wcout << red << L"Looking up app directory failed. Error "sv << GetLastError() << L'.' << lineEnd();
					goto cleanup;
				}
				// If success, trim to number of bytes actually written
				if (pathLen < filenameBuf.size())
				{
					// Null terminator is not guaranteed, remove if exists
					if (filenameBuf[pathLen - 1] == _T('\0'))
						--pathLen;
					filenameBuf.resize(pathLen);
					break;
				}
			} while (true);
		}

		// Both methods use whatever native used to run this app, so it may be DOS-style 8.3 path or a long path.
		// We'll convert it to a long path, which may be a no-op.
		pathLen = GetLongPathName(filenameBuf.data(), NULL, 0);
		if (pathLen == 0)
		{
			std::wcout << red << L"Looking up app directory failed. Error "sv << GetLastError() << L'.' << lineEnd();
			goto cleanup;
		}
		filenameBuf.resize(pathLen);

		// Reusing same buffer for short and long path is explicitly allowed
		// Writing to std::string null terminator with another null is fine in C++17, undefined behavior earlier
		pathLen = GetLongPathName(filenameBuf.data(), filenameBuf.data(), (DWORD)filenameBuf.size());
		if (pathLen == 0)
		{
			std::wcout << red << L"Looking up app directory failed. Error "sv << GetLastError() << L'.' << lineEnd();
			goto cleanup;
		}
		filenameBuf.resize(pathLen); // return if success does not include null terminator

		// Trim to last slash.
		const std::size_t lastSlash = filenameBuf.find_last_of(L"\\/"sv);
		if (lastSlash == lw_string::npos)
		{
			std::wcout << red << L"Current app path \""sv << filenameBuf << L"\" made no sense."sv << lineEnd();
			goto cleanup;
		}
		appFolder = filenameBuf.substr(0, lastSlash + 1);
	}

	// Parse passed args
	{
		bool bad = false;

		if (argc > 1)
		{
			const auto setport = [&](std::size_t argCIdxName, lw_ui16* writeTo) {
				if (argCIdxName + 1 >= argc)
				{
					std::wcout << L"Invalid cmdline: " << argv[argCIdxName] << L" had no following value.\n"sv;
					return (bad = true);
				}

				CheckPort(argv[argCIdxName + 1], writeTo, [&]() {
					std::wcout << L"Invalid cmdline: "sv << argv[argCIdxName];
					bad = true;
					});
				return !bad;
			};
			const auto setpath = [&](std::size_t argCIdxName, std::string* writeTo) {
				if (argCIdxName + 1 >= argc)
				{
					std::wcout << L"Invalid cmdline: "sv << argv[argCIdxName] << L" had no following value.\n"sv;
					return (bad = true);
				}

				// If flash policy path is specified, it must exist
				if (!lw_file_exists(WideToUTF8(argv[argCIdxName + 1]).c_str()))
				{
					std::wcout << L"Invalid cmdline: "sv << argv[argCIdxName] << L" had invalid path \"" << argv[argCIdxName + 1] << L"\".\n"sv;
					return (bad = true);
				}
				*writeTo = WideToUTF8(argv[argCIdxName + 1]);
				// PFX may hold both priv key and full chain, but should only be passed once, as priv key
				if (writeTo == &wsFullChainPath && lw_u8str_icmp(*writeTo, wsPrivKeyPath))
				{
					std::wcout << L"Invalid cmdline: \""sv << argv[argCIdxName] << L"\" cert path \""sv
						<< argv[argCIdxName + 1] << L"\" was reused for both fullchain and priv key. "
						"Only pass it for priv key if you're using a PFX with both.\n"sv;
					return (bad = true);
				}
				if (writeTo == &flashPolicyPath && (lw_u8str_icmp(*writeTo, wsFullChainPath) || lw_u8str_icmp(*writeTo, wsPrivKeyPath)))
				{
					std::wcout << L"Invalid cmdline: \""sv << argv[argCIdxName] << L"\" policy path \""sv
						<< argv[argCIdxName + 1] << L"\" was reused for a websocket cert path.\n"sv;
					return (bad = true);
				}

				return !bad;
			};
			// Assume the first argv[0] is app path, and skip it
			// otherwise read all arguments in key-value pairs, or as keys by themselves
			for (std::size_t i = 1; i < argc;)
			{
				// Skip past commandline - or / precursor
				if (argv[i][0] == L'/' || argv[i][0] == L'-')
					++argv[i];

				// These only edit the same things
				if ((!strcasecmp(argv[i], L"mainPort") && setport(i, &mainPort)) ||
					(!strcasecmp(argv[i], L"wsPort") && setport(i, &websocketNonSecurePort)) ||
					(!strcasecmp(argv[i], L"wssPort") && setport(i, &websocketSecurePort)) ||
					(!strcasecmp(argv[i], L"certFullChainPath") && setpath(i, &wsFullChainPath)) ||
					(!strcasecmp(argv[i], L"certPrivKeyPath") && setpath(i, &wsPrivKeyPath)))
				{
					i += 2;
					continue;
				}
				// Flash policy set: presumably we want flash enabled
				if (!strcasecmp(argv[i], L"flashPolicyPath") && setpath(i, &flashPolicyPath))
				{
					if (flashEnabled)
						std::wcout << L"Warning: cmdline enableFlash does not need passing if you pass the flash policy path.\n"sv;
					flashEnabled = true;
					i += 2;
					continue;
				}
				// Flash is enabled: assume it is to be generated, or read from app directory
				if (!strcasecmp(argv[i], L"enableFlash"))
				{
					// They also passed flash policy, so complain
					if (!flashPolicyPath.empty())
						std::wcout << L"Warning: cmdline "sv << argv[i] << L" does not need passing if you set the policy path.\n"sv;
					flashEnabled = true;
					++i;
					continue;
				}
				// If this is true, expects the server program to be run under admin privileges,
				// which is necessary for ICMP raw sockets (used for UDP error replies),
				// and for privileged hosting (hosting on a port number below 1024)
				if (!strcasecmp(argv[i], L"requireAdmin"))
				{
					requireAdmin = true;
					++i;
					continue;
				}
				// If this is true, turns off the statistics line and the title bar updates.
				// The ability to use cin for statistics, or send report messages, is still usable.
				if (!strcasecmp(argv[i], L"noRegularOutput"))
				{
					regularOutputEnabled = false;
					++i;
					continue;
				}
				// Sets the TLS certificate private password; note the server does not explicitly store
				// this securely, it depends on SChannel or OpenSSL's storage.
				if (!strcasecmp(argv[i], L"certPassPhrase"))
				{
					if (i + 1 >= argc)
					{
						std::wcout << L"Invalid cmdline: "sv << argv[i] << L" had no following value.\n"sv;
						bad = true;
						break;
					}
					wsPassPhrase = WideToUTF8(argv[i + 1]);
					if (wsPassPhrase[0] == L'"')
					{
						wsPassPhrase.erase(0);
						wsPassPhrase.erase(wsPassPhrase.cend());
					}
					i += 2;
					continue;
				}
				if (!strcasecmp(argv[i], L"welcomeMsg"))
				{
					if (i + 1 >= argc)
					{
						std::wcout << L"Invalid cmdline: "sv << argv[i] << L" had no following value.\n"sv;
						bad = true;
						break;
					}
					welcomeMessage = WideToUTF8(argv[i + 1]);
					i += 2;
					continue;
				}
				if (!strcasecmp(argv[i], L"tcpClientUploadCap") || !strcasecmp(argv[i], L"totalUploadCap"))
				{
					if (i + 1 >= argc)
					{
						std::wcout << L"Invalid cmdline: "sv << argv[i] << L" had no following value.\n"sv;
						bad = true;
						break;
					}
					const std::uint32_t capBytes = static_cast<std::uint32_t>(std::wcstoul(argv[i + 1], nullptr, 10));
					if (capBytes < 0)
					{
						std::wcout << L"Invalid cmdline: "sv << argv[i] << L" had invalid value "sv << capBytes << L" bytes.\n"sv;
						bad = true;
						break;
					}
					if (!_wcsicmp(argv[i], L"tcpClientUploadCap"))
						tcpClientUploadCap = (std::size_t)capBytes;
					else
						totalUploadCap = (std::size_t)capBytes;
					i += 2;
					continue;
				}
				// Give help
				if (!strcasecmp(argv[i], L"?") || !strcasecmp(argv[i], L"help"))
				{
					std::wcout << L"==== " PROJECT_NAME " "sv;
#					ifdef _DEBUG
					std::wcout << L"debug"sv;
#					else // !_DEBUG
					std::wcout << L"release"sv;
#					endif // _DEBUG
					std::wcout << L" build "sv << lacewing::relayserver::buildnum << L" cmdline options ====\n"
						"bluewing-cpp-server /welcomeMsg \"message\" /mainPort 6121\n"
						"  /enableFlash /flashPolicyPath \"path to xml\"\n"
						"  /wsPort 80 /wssPort 443 /certFullChainPath \"...full-chain.pem\" /certPrivKeyPath \"...privkey.pem\" /certPassPhrase \"password\"\n"
						"  /requireAdmin /noRegularOutput /tcpClientUploadCap bytespersec /totalUploadCap bytespersec\n"
						"\n"
						"Defaults if command-lines and passed, and nothing is specified:\n"
						"  Main port 6121. Flash and WebSocket not hosting.\n"
						"  To reply to invalid UDP with ICMP Unreachable, the server app must be running with admin permissions.\n"
						"  Cert chain will be loaded from fullchain.pem + privkey.pem files, or from tlscert.pfx, in current directory.\n"
						"    No password is expected, if none is provided by cmdline.\n"
						"  Flash will be disabled by default. If enabled, it will always host policy on port 843.\n"
						"    Specifying /enableFlash without /flashPolicyPath will generate a flash policy in current directory.\n"
						"  Admin will not be required.\n"
						"  Regular output is on, so a status line is maintained at end of console, and console colors/title set is used.\n"
						"  TCP caps will be unlimited for both single-client (tcpClientUploadCap) and all-client (totalUploadCap).\n"
						"  UDP cap is 4/5th of TCP cap, so that UDP will not be the cause of exceeding the client cap.\n"
						"  Welcome message will contain build number, and if upload caps are active, will warn about automatic bans.\n"
						"====\n"sv;
					bad = true;
					break;
				}

				if (bad)
					break;

				std::wcout << L"Invalid cmdline: "sv << argv[i] << L" was not recognised.\n"sv;
				bad = true;
				break;
			}
		}

		if (bad)
			goto cleanup;
	}

	// Backup current console config for restoring
	// GetConsoleMode fails if not console (e.g. redirected stdout to file)
	isConsoleOutput = regularOutputEnabled && GetConsoleMode(hStdOut, &conOrigOutputMode);

	if (isConsoleOutput)
	{
		// Save the console details for restoring at end of app
		GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &conOrigInputMode);
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(hStdOut, &csbi);
		conOrigTextAttributes = csbi.wAttributes;
		GetConsoleCursorInfo(hStdOut, &conOrigCursorInfo);


		// Set console icon
		{
			// GetConsoleWindow() and undoc'd Kernel32 func SetConsoleIcon() doesn't work in Win 11,
			// presumably due to psuedoconsole.
			// GetForegroundWindow() will grab any app's foreground window, not just this one.
			consoleWin = GetActiveWindow();
			int width = GetSystemMetrics(SM_CXSMICON), height = GetSystemMetrics(SM_CYSMICON);
			conSmallIcon = (HICON)LoadImageW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON,
				width, height, LR_LOADTRANSPARENT | LR_COLOR | LR_COPYFROMRESOURCE);
			conOrigSmallIcon = (HICON)SendMessageW(consoleWin, WM_SETICON, ICON_SMALL, (LPARAM)conSmallIcon);
			width = GetSystemMetrics(SM_CXICON);
			height = GetSystemMetrics(SM_CYICON);
			conBigIcon = (HICON)LoadImageW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON,
				width, height, LR_LOADTRANSPARENT | LR_COLOR | LR_COPYFROMRESOURCE);
			conOrigBigIcon = (HICON)SendMessageW(consoleWin, WM_SETICON, ICON_BIG, (LPARAM)conBigIcon);
		}

		// Same as outputting gray but without time buffer
		SetConsoleTextAttribute(hStdOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}

	// Check for admin membership, required for ICMP raw sockets, which are used for UDP error replies
	// Blue Server does not *require* ICMP replies though; it will silently ignore bad UDP (e.g. from an unrecognised IP)
	{
		BOOL isAdmin;
		SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
		PSID AdministratorsGroup;
		isAdmin = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
			&AdministratorsGroup);
		if (isAdmin)
		{
			if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin))
				isAdmin = FALSE;
			FreeSid(AdministratorsGroup);
		}
		if (!isAdmin)
		{
			if (requireAdmin)
			{
				std::wcout << red << L"Server is set by command-line to require admin, and is not running as admin. Server start aborted.\n"sv;
				goto cleanup;
			}
			std::wcout << red << L"Warning: server is not running with admin privileges. Resetting UDP connections with ICMP will not be possible.\n"sv;
		}
	}

	// If console output, and no cmd args were passed at all, ask user for input
	if (argc <= 1)
	{
		if (!GetPortFromInput(L"main"sv, &mainPort, false, 6121) ||
			!GetPortFromInput(L"WebSocket insecure"sv, &websocketNonSecurePort, false, 80) ||
			!GetPortFromInput(L"WebSocket secure"sv, &websocketSecurePort, true, 443))
		{
			goto cleanup;
		}
		if (welcomeMessage.empty() && requestUserInput)
		{
			std::wcout << userpromptcolor << L"Enter a welcome message, or leave blank for the default message with server build:\n"sv;
			welcomeMessage = WideToUTF8(GetConsoleLine());
		}
	}
	else // Set defaults
	{
		if (!mainPort)
			mainPort = 6121;
		// Secure port passed but no cert: can we guess it? If not, hard fail
		if (websocketSecurePort && wsFullChainPath.empty())
		{
			GuessCertPath();
			if (wsFullChainPath.empty())
			{
				std::wcout << red << L"Server was passed secure port but no certificate paths.\n"sv;
				goto cleanup;
			}
		}
	}

	// Block some IPs by default
	//misbehavingIPList.emplace_back(MisbehavingIPEntry("127.0.0.1"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, std::string_view(), laceclock::now() + 24h));
	misbehavingIPList.emplace_back(MisbehavingIPEntry("176.59.131.111"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, std::string_view(), laceclock::now() + 24h));

	// Stop echoing std::wcin keypresses to std::wcout display, and disable line buffering.
	// Line buffering is where std::wcin will buffer until Enter, resulting in no key registering,
	// including in getch().
	// This is referred to on Linux as a "cooked" or "canonical" mode.
	// Disabling it causes any character to be put straight into std::wcin, without buffering.
	// This allows various "is input pending" functions to work on single keypress.
	if (isConsoleOutput)
	{
		if (SetConsoleMode(hStdIn, conOrigInputMode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)) == FALSE)
		{
			std::wcout << red << L"Failed to set stdin to character mode (error "sv << GetLastError() << L"). "
				"Server may not process console input keypresses."sv << lineEnd();
		}
	}

	// User input is not echoed to output screen anymore, so we don't need cin and cout sync'd
	std::wcin.tie(nullptr);

	globalpump = lacewing::eventpump_new();
	globalserver = new lacewing::relayserver(globalpump);
	globalmsgrecvcounttimer = lacewing::timer_new(globalpump, "global message receiving tick-over");

	// Update the current time in case host() errors, or try to connect before first tick
	OnTimerTick(globalmsgrecvcounttimer);

	if (!welcomeMessage.empty())
	{
		globalserver->setwelcomemessage(welcomeMessage);
		welcomeMessage.clear();
	}
	else
	{
		std::stringstream welcMsg;
#ifdef _DEBUG
		welcMsg << "This is a Bluewing Server build "sv << lacewing::relayserver::buildnum <<
			". Currently under debug testing. You may be disconnected randomly as server is restarted."sv;
#else // !_DEBUG
		if (tcpClientUploadCap)
		{
			welcMsg << "This is a Bluewing Server build "sv << lacewing::relayserver::buildnum <<
				". An upload cap is in place. Please pay attention to Sent server -> peer text messages on subchannels 0 and 1,"
				" or you may be banned."sv;
		}
		else
			welcMsg << "This is a Bluewing Server build "sv << lacewing::relayserver::buildnum << '.';
#endif // _DEBUG
		globalserver->setwelcomemessage(welcMsg.str());
	}

	// Initialise hooks
	globalserver->onconnect(OnConnectRequest);
	globalserver->ondisconnect(OnDisconnect);
	globalserver->onmessage_server(OnServerMessage);
	globalserver->onmessage_channel(OnChannelMessage);
	globalserver->onmessage_peer(OnPeerMessage);
	globalserver->onerror(OnError);
	globalmsgrecvcounttimer->on_tick(OnTimerTick);

	// Allow all letters, all numbers, all marks like accents, all punctuation, and char 32 i.e. space
	globalserver->setcodepointsallowedlist(lacewing::relayserver::codepointsallowlistindex::ClientNames, "L*,M*,N*,P*,32");
	globalserver->setcodepointsallowedlist(lacewing::relayserver::codepointsallowlistindex::ChannelNames, "L*,M*,N*,P*,32");
	// globalserver->setcodepointsallowedlist(lacewing::relayserver::codepointsallowlistindex::MessagesSentToClients, "L*,M*,N*,P*,32");

	// If you change this, make sure character 33 is excluded, as it is the ANSI console command starter
	globalserver->setcodepointsallowedlist(lacewing::relayserver::codepointsallowlistindex::MessagesSentToServer, "L*,M*,N*,P*,32");
	//globalserver->setinactivitytimer(36000000);

	UpdateTitle(0); // Update console title with 0 clients

	// We only expect flash policy not to exist, if flashPolicyPath was not set by user.
	if (flashEnabled && flashPolicyPath.empty())
	{
		GenerateFlashPolicy(mainPort);
		if (flashPolicyPath.empty())
			return 1;
	}

	// Host the thing
	std::wcout << green << L"Host started. Port "sv << mainPort << L", build "sv << globalserver->buildnum << L". "sv
		<< (flashEnabled ? L"Flash policy hosting on TCP port 843"sv : L"Flash not hosting"sv) << L'.' << lineEnd();

	// For loading from Windows certificate store (certmgr.msc), use e.g. websocket->load_sys_cert("Root", "yourdomain.com", "LocalMachine")
	if (websocketSecurePort &&
		!globalserver->websocket->load_cert_file(wsFullChainPath.c_str(), wsPrivKeyPath.c_str(), wsPassPhrase.c_str()))
	{
		if (wsFullChainPath == wsPrivKeyPath)
		{
			std::wcout << red << L"Found but couldn't load TLS certificate file \""sv << UTF8ToWide(wsFullChainPath)
				<< L"\". Aborting server start."sv << lineEnd();
		}
		else
		{
			std::wcout << red << L"Found but couldn't load TLS certificate files \""sv << UTF8ToWide(wsFullChainPath) << L"\", \""sv
				<< UTF8ToWide(wsPrivKeyPath) << L"\". Aborting server start."sv << lineEnd();
		}
		goto cleanup;
	}

	if (websocketNonSecurePort || websocketSecurePort)
	{
		std::wcout << green << L"WebSocket hosting. Port "sv;
		if (websocketNonSecurePort)
			std::wcout << websocketNonSecurePort << L" (non-secure, ws://xx)"sv;
		if (websocketNonSecurePort && websocketSecurePort)
			std::wcout << L" and port "sv;
		if (websocketSecurePort)
			std::wcout << websocketSecurePort << L" (secure, wss://xx)"sv;
		std::wcout << L'.' << lineEnd(false);
	}


	lastTimeAndStatsSS.imbue(std::locale(std::string()));
	setlocale(LC_ALL, ""); // set user's locale for C functions like strftime

	ReprintStatisticsLine();

	startTime = time(NULL);
	globalserver->host(mainPort);

	if (!flashPolicyPath.empty())
		globalserver->flash->host(flashPolicyPath.c_str());

	if (websocketNonSecurePort || websocketSecurePort)
		globalserver->host_websocket(websocketNonSecurePort, websocketSecurePort);

	// Update messages received/sent line every 1 sec
	globalmsgrecvcounttimer->start(1000L);

	// Hide console cursor by default - otherwise the statistics line \r makes it flash at start of line (ugly)
	if (isConsoleOutput)
	{
		CONSOLE_CURSOR_INFO info{ 100, FALSE };
		SetConsoleCursorInfo(hStdOut, &info);

		// In case this is set to false due to running under debugger, enable it again
		requestUserInput = true;
	}

	// Start main event loop
	{
		lacewing::error error = nullptr;
#ifdef _DEBUG
		error = globalpump->start_eventloop();
#else // !_DEBUG
		try {
			error = globalpump->start_eventloop();
		}
		catch (...)
		{
			error = lacewing::error_new();
			error->add("Crash happened.");
		}
#endif // _DEBUG

		if (error)
			std::wcout << red << L"Error occurred in pump: "sv << error->tostring() << lineEnd();
	}

	// ==================================================================
	// Close down the server
	// ==================================================================
cleanup:
	shutdowned = true;
	lastTimeAndStats.clear();
	clientdata.clear(); // Free our client shared refs before we stop global server
	lacewing::timer_delete(globalmsgrecvcounttimer);
	const bool goodInit = globalserver != nullptr;
	if (goodInit)
	{
		globalserver->unhost();
		globalserver->flash->unhost();
		globalserver->unhost_websocket(true, true);
		delete globalserver;
	}
	lacewing::eventpump_delete(globalpump);

	// If we generated a flash policy, delete it
	if (!flashPolicyPath.empty() && deleteFlashPolicyAtEndOfApp)
	{
		DeleteFile(UTF8ToWide(flashPolicyPath).c_str());
	}

	// Lacewing uses a sync inside lw_trace, which is singleton and never freed.
	// lw_trace() is a no-op if _lacewing_debug isn't defined.
	// To let garbage collector not see it as a leak:
#if defined(_CRTDBG_MAP_ALLOC) && defined(_lacewing_debug)
	lw_sync_delete(lw_trace_sync);
#endif // CRT + Debug

	// If we inited properly, show the end app stats
	if (goodInit)
		PrintTotalStatistics(true);

	// Restore input-output stream sync
	std::wcin.tie(&std::wcout);

	// Restore console config for next app
	// We only changed it if it was a console output anyway
	if (isConsoleOutput)
	{
		// User should press any key to exit - this allows users who run the server exe directly
		// to read the statistics or copy them out before close.
		// If not console output, then user is redirecting output to file and input is likely dead
		if (requestUserInput)
		{
			// Reset error flags to allow new input, and clear any random keypresses user did before now
			std::wcin.clear();
			while (cinInputPending())
				std::wcin.get();
			std::wcout << std::flush;

			// Count programs attached to this console. If 1, server was run directly, e.g. by double-clicking EXE.
			// If server was run indirectly, via cmd, it will be 2 (or if we made room, more)
			// and we don't need to pause at end of app.
			DWORD procIDs[2], maxCount = 2, result = GetConsoleProcessList((LPDWORD)procIDs, maxCount);
			if (result == 1)
				requestUserInput = false;
		}
		
		// Erase current line to end, then set console cursor visible
		SetConsoleCursorInfo(hStdOut, &conOrigCursorInfo);
		std::wcout << L'\r';

		// Read one character
		if (requestUserInput)
		{
			std::wcout << gray << L"Press any key to exit.\n"sv << std::flush;
			std::wcin.get();
		}

		// Restore console modes
		SetConsoleMode(hStdOut, conOrigOutputMode);
		SetConsoleMode(hStdIn, conOrigInputMode);
		SetConsoleTextAttribute(hStdOut, conOrigTextAttributes);
		SetConsoleCursorInfo(hStdOut, &conOrigCursorInfo);

		// Reset console icons
		SendMessage(consoleWin, WM_SETICON, ICON_SMALL, (LPARAM)conOrigSmallIcon);
		SendMessage(consoleWin, WM_SETICON, ICON_BIG, (LPARAM)conOrigBigIcon);
		DestroyIcon(conOrigSmallIcon);
		DestroyIcon(conOrigBigIcon);
	}
	std::wcout << std::flush;

	return !goodInit;
}

void UpdateTitle(std::size_t clientCount)
{
	// We can't set title if we don't have a console
	if (!isConsoleOutput)
		return;
	std::size_t channelCount = globalserver->channelcount();
	lw_char name[128];
	_stprintf_s(name, std::size(name), L"Bluewing C++ Server - %zu client%s connected in %zu channel%s",
		clientCount, clientCount == 1 ? L"" : L"s",
		channelCount, channelCount == 1 ? L"" : L"s");
	SetConsoleTitle(name);

	if (serverstats.maxClients < clientCount)
		serverstats.maxClients = clientCount;
	if (serverstats.maxChannels < channelCount)
		serverstats.maxChannels = channelCount;
}

// Trusted IPs can ask for statistics and unban any IP, and cannot be banned themselves
static bool IsIPTrusted(const std::string_view addr)
{
	// Allow only from LAN addresses, and Darkwire
	// This does not check IPv6 addresses, you may want to do that
	return addr.substr(0, 3) == "10."sv || // class A private
		// Class B private is subsection of 172.16.x.x and not checked for here
		(addr.size() > "192.168.1."sv.size() && addr.substr(0, "192.168.1."sv.size()) == "192.168.1."sv) || // class C private
		addr == "127.0.0.1"sv || // localhost
		addr == "80.229.219.2"sv; // Darkwire
}

/**
 * @brief Handles connect requests. Server must respond with server.connect_response().
 * @param server The Bluewing server, always globalserver.
 * @param client The client requesting a connection.
 * @remarks
 * Clients will be at step 4 of handshake, so UDP is not ready yet. Blasting a message after connect_response() will usually fail.
 * Any write-interaction with client before connect_response() will result in undefined behavior,
 * but it is valid to write in this handler immediately after connect_response().
 * Calling connect_response() twice for a client will cause an error.
*/
void OnConnectRequest(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> client)
{
	const std::string addr = client->getaddress();
	const lw_string addrW(UTF8ToWide(client->getaddress()));

	// If IP was marked as misbehaving
	const auto entry = std::find_if(misbehavingIPList.begin(), misbehavingIPList.end(),
		[&](const MisbehavingIPEntry &b) { return b.ip == addr; });
	if (entry != misbehavingIPList.end())
	{
		const auto now = std::chrono::steady_clock::now();
		// Their entry has expired, discard it and continue
		if (entry->resetAt < now)
			misbehavingIPList.erase(entry);
		// They have committed too many infractions, they are currently banned
		else if (entry->disconnects > 3)
		{
			// Extend ban, and log only if the user isn't reconnect-spamming
			entry->resetAt = now + std::chrono::hours(entry->disconnects++ << 2);
			if (entry->nextLogLine < now)
			{
				std::wcout << yellow << L"Blocked connection attempt from IP "sv << addrW << L", banned due to "sv
					<< UTF8ToWide(entry->reason) << L'.' << lineEnd();
			}
			entry->nextLogLine = now + 1min;
			return server.connect_response(client, entry->reason.c_str());
		}
	}

	// Allow connection
	server.connect_response(client, std::string_view());
	UpdateTitle(server.clientcount());

	std::wcout << green << L"New client ID " << client->id() << L", IP "sv << addrW << L" connected."sv << lineEnd();
	clientdata.push_back(std::make_unique<clientstats>(client));
}

/**
 * @brief Handles client disconnect events.
 * @param server The server, always globalserver.
 * @param client The client, never null.
 * @remarks
 * You may have disconnects reported via OnError, if the connection was not Relay.
*/
void OnDisconnect(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> client)
{
	UpdateTitle(server.clientcount());
	std::string name = client->name();
	name = !name.empty() ? name : "[unset]"sv;
	const std::string addr = client->getaddress();

	// A client that is not Relay will not have called OnConnect, so we won't have a data for it
	const auto cd = ClientDataByClientPtr(client);
	std::wcout << green << L"Client ID "sv << client->id() << L", name "sv << UTF8ToWide(name) << L", IP "sv << UTF8ToWide(addr) << L" disconnected."sv;
	if (cd != clientdata.cend())
		std::wcout << L" Uploaded "sv << (**cd).total.bytes << L" bytes in "sv << (**cd).total.msg << L" msgs total."sv;
	std::wcout << lineEnd();

	// client.istrusted() indicates whether the client sent invalid Bluewing messages, and is getting kicked
	// for violations, or whether the client is disconnecting of its own accord.
	if (!client->istrusted() && !IsIPTrusted(addr))
	{
		const auto entry = std::find_if(misbehavingIPList.begin(), misbehavingIPList.end(), [&](const MisbehavingIPEntry & b) { return b.ip == addr; });
		if (entry == misbehavingIPList.end())
		{
			std::wcout << yellow << L"Due to malformed protocol usage, created a IP ban entry."sv << lineEnd();
			AddMisbehavingIPEntry(**cd, addr, "Broken Lacewing protocol", laceclock::now() + 30min);
		}
		else
		{
			std::wcout << yellow << L"Due to malformed protocol usage, increased their ban likelihood."sv << lineEnd();
			++entry->disconnects;
		}
	}
	if (cd != clientdata.cend())
		clientdata.erase(cd);
}

/**
 * @brief Ticks over second-based statistics, and bans users who have exceeded TCP upload cap.
 * @param timer The one-second timer, always globalmsgrecvcounttimer.
*/
void OnTimerTick(lacewing::timer timer)
{
	std::time_t rawtime = std::time(NULL);
	std::tm timeinfo = { 0 };
	std::time(&rawtime);
	// Gets time and separator. %T is locale-independent.
	if (!localtime_s(&timeinfo, &rawtime))
		std::_tcsftime(timeBuffer, std::size(timeBuffer), L"%T | ", &timeinfo);

	// We're in startup, and only want to update the time
	if (!timer)
		return;

	serverstats.in.highestSec.SetToMaxOfCurrentAndThis(serverstats.in.cur);
	serverstats.out.highestSec.SetToMaxOfCurrentAndThis(serverstats.out.cur);
	serverstats.in.total += serverstats.in.cur;
	serverstats.out.total += serverstats.out.cur;
	serverstats.in.lastSec = serverstats.in.cur;
	serverstats.out.lastSec = serverstats.out.cur;
	serverstats.in.cur = serverstats.out.cur = { 0, 0 };

	// Prepare new statistics line, and print it at bottom of screen
	if (isConsoleOutput)
	{
		lastTimeAndStatsSS << L"Last sec received "sv << serverstats.in.lastSec.msg << L" messages ("sv << serverstats.in.lastSec.bytes
			<< L" bytes), forwarded "sv << serverstats.out.lastSec.msg << L" ("sv << serverstats.out.lastSec.bytes << L" bytes).\r"sv;
		lastTimeAndStats = lastTimeAndStatsSS.str();
		lastTimeAndStatsSS.clear();
		lastTimeAndStatsSS.str(lw_string());
		ReprintStatisticsLine();
	}

	// If user has pressed keys on console
	if (cinInputPending())
	{
		int cinKey = std::wcin.get();
		// Space key: write statistics
		if (cinKey == L' ')
			statsDump = true;

		else // Unrecognised, do a warning beep
			std::wcout << L'\a';
	}

	// Dump total server statistics so far
	// Windows may trigger by pressing Ctrl-Break, Linux by pressing Ctrl-Z .
	if (statsDump)
	{
		statsDump = false;
		PrintTotalStatistics(false);
	}

	for (auto& c : clientdata)
	{
		if (!c->exceeded)
		{
			c->highestSec.SetToMaxOfCurrentAndThis(c->cur);
			c->total += c->cur;
			c->lastSec = c->cur;
			c->cur = { 0, 0 };
		}
	}

	if (tcpClientUploadCap)
	{
		// open clientdata as shared owner, or disconnect handler's erase may invalidate it while TimerTick is still using it
		for (auto cliData : clientdata)
		{
			if (!cliData->exceeded)
				continue;
			const std::string addr = cliData->client->getaddress();

			if (IsIPTrusted(addr))
				continue;

			std::string banReason = "You have been banned for heavy TCP usage."s + contactMsg;
			const auto banEntry = std::find_if(misbehavingIPList.begin(), misbehavingIPList.end(),
				[&](const MisbehavingIPEntry& b) { return b.ip == addr; });
			if (banEntry == misbehavingIPList.end())
				AddMisbehavingIPEntry(*cliData, addr, banReason, laceclock::now() + 1h);
			else
				++banEntry->disconnects;

			std::wcout << red << L"Client ID "sv << cliData->client->id() << L", IP "sv << UTF8ToWide(addr) <<
				L" dropped for heavy TCP upload ("sv << cliData->cur.bytes << L" bytes in "sv << cliData->cur.msg << L" msgs)"sv << lineEnd();
			const std::string kickReason = "You have exceeded the TCP upload limit."s + contactMsg;
			cliData->client->send(1, kickReason, 0);
			cliData->client->send(0, kickReason, 0);
			cliData->client->disconnect(nullptr, 1008); // 1008 = WebSocket Policy Violation code, used for rate limiting

			// disconnect() will usually call disconnect handler, but rarely won't.
			// If it does call the handler, the handler will delete the clientdata "cliData", so this for loop running through clientdata
			// is now invalid, so we have to break or we get exception from invalid iterator.
			// If it doesn't call the handler, we need to erase "cliData" or we'll get a disconnect re-attempted every timer tick.
			const auto a = ClientDataByClientPtr(cliData->client);
			if (a != clientdata.cend())
				clientdata.erase(a);
			break;
		}
	}
	UpdateTitle(globalserver->clientcount());
}

/**
 * @brief Handles Lacewing Blue server errors by reporting them to console.
 * @param server Server, always globalserver
 * @param error  Error struct
*/
void OnError(lacewing::relayserver &server, lacewing::error error)
{
	std::string_view err = error->tostring();
	if (err.back() == '.')
		err.remove_suffix(1);
	std::wcout << red << L"Error occured: "sv << UTF8ToWide(err) << L". Execution continues."sv << lineEnd();
}

/**
 * @brief Responds to messages from client to server directly.
 * @param server		Server, always globalserver
 * @param senderclient	Client sending, never null
 * @param blasted		If true, sent over UDP or faux-UDP, else sent over TCP.
 * @param subchannel	Subchannel, 0 to 255 inclusive.
 * @param data			The message
 * @param variant		The message variant (0 = UTF-8 text, 1 = int32 number, 2 = binary).
 * @remarks Bluewing library automatically verifies UTF-8 text in text variant messages, and that number is 4 bytes.
 * Text inside binary is not checked, as binary messages are opaque.
*/
void OnServerMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	serverstats.in.cur.AddMsg(data.size());

	// If you want to log all incoming messages to console e.g. for debug, here is a way
	if constexpr (false)
	{
		std::string name = senderclient->name();
		name = !name.empty() ? name : "[unset]"sv;

		std::wcout << gray << L"Message from client ID "sv << senderclient->id() << L", name "sv << UTF8ToWide(name)
			<< L':' << lineEnd(false) << UTF8ToWide(data) << lineEnd(false)
			<< L"blasted = "sv << (blasted ? L"yes"sv : L"no"sv)
			<< L", subchannel = "sv << subchannel << L", variant = "sv << variant
			<< L'.' << lineEnd();
	}

	// Ping reply (old style)
	if (subchannel == 0 && variant == 2 && data.size() == 0)
	{
		if (blasted)
			senderclient->blast(0, std::string_view{}, 2);
		else
			senderclient->send(0, std::string_view{}, 2);
		return;
	}

	// The default messages handled in bluewing-cpp-server, which are not required by Bluewing,
	// are only text messages that are TCP on subchannel 0.
	if (blasted || variant != 0 || subchannel != 0)
	{
		const std::string addr = senderclient->getaddress();
		std::wcout << red << L"Dropped server message from IP "sv << UTF8ToWide(addr) << L", invalid type."sv << lineEnd();
		const auto cd = ClientDataByClientPtr(senderclient);
		if (cd != clientdata.cend())
		{
			// Add the final server msg to total
			(**cd).cur.AddMsg(data.size());

			if (IsIPTrusted(addr))
				return;

			if ((**cd).wastedServerMessages++ > 5)
			{
				const auto banEntry = GetMisbehavingEntryByIP(addr);
				if (banEntry == misbehavingIPList.end())
					AddMisbehavingIPEntry(**cd, addr, "Sending too many messages the server is not meant to handle."sv, laceclock::now() + 1h);
				else
					++banEntry->disconnects;
				const std::string kickReason = "You have been banned for sending too many server messages that the server is not "
					"designed to receive."s + contactMsg;
				senderclient->send(1, kickReason);
				senderclient->disconnect();
			}
		}
		return;
	}

	// Default bluewing-cpp-server messages include:
	// All users:
	// * A client can request their remote IP (added in build 40 of bluewing-cpp-server)
	//   "get my remote ip"
	//   Reply is client's remote IPv4 "1.2.3.4" or IPv6 "[xx]".
	//
	// 
	// A user is trusted if their IP matches IsIPTrusted().
	// Trusted IPs have extra commands. If user is not trusted, the message is ignored.
	// 
	// Trusted users:
	// * A report of server, including client list, channel list, ban list, and statistics.
	//   "send report"
	//   Reply is a detailed, LF-separated report.
	// * A request to immediately unban an IP.
	//   "unban 1.2.3.4" for IPv4 or "unban [xx]" for IPv6
	//   Reply is number of ban entries removed, or if it was not found in ban list.
	//
	// You can remove these handlers if you don't need them (or remove OnServerMessage entirely).

	// The remote IP request is "get my remote ip", and any user can request it.
	if (data == "get my remote ip"sv)
	{
		std::string msg = "IP: "s;
		msg += senderclient->getaddress();
		senderclient->send(0, msg);
		return;
	}

	// Report client list, channel list, ban list, and server statistics
	if (data == "send report"sv || (data.size() > 6 && data.substr(0, 6) == "unban "sv))
	{
		const std::string addr = senderclient->getaddress();

		if (IsIPTrusted(addr))
		{
			std::stringstream str;
			str << std::boolalpha;
			// Enable the server's local user preferred date-time and large number format.
			// including thousands separators.
			str.imbue(std::locale(std::string()));

			if (data == "send report"sv)
			{
				str << "Reporting server status. Channel count: "sv << globalserver->channelcount() << ", client count: "sv << globalserver->clientcount() << ".\n\n"sv;
				str << "=== Channel list:\n"sv;
				{
					auto readLock = globalserver->lock_channellist.createReadLock();
					const auto& channels = globalserver->getchannels();
					for (auto& c : channels)
					{
						str << "\u2022 Channel \""sv << c->name() << "\", ID "sv << c->id() << ", hidden "sv << c->hidden() << ", autoclose "sv << c->autocloseenabled() << ", client list:\n"sv;
						auto chReadLock = c->lock.createReadLock();
						const auto& clientList = c->getclients();
						const auto& master = c->channelmaster();
						for (auto& cli : clientList)
						{
							str << u8"  \u25E6 Client ID "sv << cli->id() << ", name \""sv << cli->name() << "\"."sv;
							str << (cli == master ? " [channel master]\n"sv : "\n"sv);
						}
						str << '\n';
					}
					str << '\n';
				}

				{
					str << "=== Client list:\n"sv;
					auto readLock2 = globalserver->lock_clientlist.createReadLock();
					const auto& clients = globalserver->getclients();
					for (auto& c : clients)
					{
						str << "\u2022 Client \""sv << c->name() << "\", ID "sv << c->id() << ", address \""sv << c->getaddress() << "\".\n"sv;
						{
							const auto cd = ClientDataByClientPtr(c);
							if (cd != clientdata.cend())
							{
								str << "  Last second: sent "sv << (*cd)->lastSec.bytes << " bytes, "sv << (*cd)->lastSec.msg << " msgs.\n"sv;
								str << "  Total: sent "sv << (*cd)->total.bytes << " bytes, "sv << (*cd)->total.msg << " msgs.\n"sv;
							}
							else
								str << "  (no stats found)\n"sv;
						}

						str << "  Client's channel list:\n"sv;
						auto cliReadLock3 = c->lock.createReadLock();
						const auto& channelList2 = c->getchannels();
						if (channelList2.empty())
							str << "  (no channels)\n"sv;
						else
						{
							for (auto& ch : channelList2)
							{
								str << u8"  \u25E6 Channel ID "sv << ch->id() << ", \""sv << ch->name() << "\"."sv;
								str << (ch->channelmaster() == c ? " [this client is master]\n"sv : " [not master]\n"sv);
							}
						}
					}
				}

				const std::time_t curTime = time(NULL);
				const std::uint64_t secondsUp = std::max<std::uint64_t>(1, (std::uint64_t)std::ceil(difftime(curTime, startTime)));
				// Division is floor by default
				const std::uint64_t hours = secondsUp / (60ULL * 60ULL), minutes = (secondsUp / 60ULL) % 60ULL, seconds = secondsUp % 60ULL;
				str << "\n=== Total server stats so far:\n"sv
					<< "Last second: "sv << serverstats.in.lastSec.bytes << " bytes in, in "sv << serverstats.in.lastSec.msg << " msgs, "sv
					<< serverstats.out.lastSec.bytes << " bytes out, in "sv << serverstats.out.lastSec.msg << " msgs.\n"sv
					<< "Biggest second: "sv << serverstats.in.highestSec.bytes << " bytes in. "sv << serverstats.in.highestSec.msg << " msgs in. "sv
					<< serverstats.out.highestSec.bytes << " bytes out. "sv << serverstats.out.highestSec.msg << " msgs out.\n"
					<< "Average per second: "sv << (serverstats.in.total.bytes / secondsUp) << " bytes in. "sv << serverstats.in.total.msg << " msgs in. "sv
					<< (serverstats.out.total.bytes / secondsUp) << " bytes out. "sv << (serverstats.out.total.msg / secondsUp) << " msgs out.\n"sv
					<< "Total run: "sv << serverstats.in.total.bytes << " bytes in, in "sv << serverstats.in.total.msg << " msgs, "sv
					<< serverstats.out.total.bytes << " bytes out, in "sv << serverstats.out.total.msg << " msgs.\n"sv
					<< "Max num clients in this run: "sv << serverstats.maxClients << ". Max channels: "sv << serverstats.maxChannels << ".\n"sv
					<< "Start time: "sv << WideToUTF8(fulltimetostring(startTime)) << ". Current time: "sv << WideToUTF8(fulltimetostring(curTime)) << ".\n"sv
					<< "Hosting for: "sv << hours << " hrs, "sv << minutes << " mins, "sv << seconds << " seconds ("sv << secondsUp << " seconds total).\n"sv
					<< "\n=== Ban list has "sv << misbehavingIPList.size() << " entries:\n"sv;
				if (misbehavingIPList.empty())
					str << "  (list empty)"sv;
				else
				{
					std::tm* ptm;
					for (auto& b : misbehavingIPList)
					{
						const time_t resetAt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()
							+ std::chrono::duration_cast<std::chrono::system_clock::duration>(b.resetAt - laceclock::now()));
						ptm = std::gmtime(&resetAt);
						// Format: hh:mm:ssPM 23/12/25
						char time[64];
						std::strftime(time, sizeof(time), "%I:%M:%S%p %x", ptm);
						str << "\u2022 "sv << b.ip << " : banned until "sv << time << " UTC, due to \""sv << b.reason
							<< "\", num disconnects "sv << b.disconnects << ". Channel list at disconnect: "sv << b.chListAtDisconnect << ".\n"sv;
					}
				}
				str << "Report completed."sv;
			}
			else if (data.size() > 6 && data.substr(0, 6) == "unban "sv)
			{
				const std::string_view ipToUnban = data.substr(6);
				str << "Unbanning IP \""sv << ipToUnban << "\"... "sv;
				std::size_t numFound = 0;
				while (true)
				{
					auto banEntry = GetMisbehavingEntryByIP(ipToUnban);
					if (banEntry == misbehavingIPList.cend())
						break;
					misbehavingIPList.erase(banEntry);
					++numFound;
				}
				if (numFound == 0)
					str << "IP not found; failed."sv;
				else
					str << "IP found and removed in "sv << numFound << " entries."sv;
			}

			std::string msg = str.str();
			// Replace LF newlines with CRLF for Windows clients
			if (senderclient->getimplementationvalue() == lacewing::relayserver::client::clientimpl::Windows ||
				senderclient->getimplementationvalue() == lacewing::relayserver::client::clientimpl::Windows_Unicode)
			{
				for (std::size_t i = msg.find('\n'); i != std::string::npos; i = msg.find('\n', i + 2))
					msg.insert(i, 1, '\r');
			}
			senderclient->send(0, msg);
			return;
		}
	}

	// Otherwise, the message is assumed to be something the user intended to display on the console.
	// We don't have to sanitize name here (e.g. to prevent console cmds) due to ClientNames allowlist.
	std::string name = senderclient->name();
	name = !name.empty() ? name : "[unset]"sv;

	std::wcout << gray << L"Message from client ID "sv << senderclient->id()
		<< L", name "sv << UTF8ToWide(name) << L':' << lineEnd(false)
		<< UTF8ToWide(data) << lineEnd();
}

/**
 * Adds a message size and 1 to count of the client
 * @return true if client has not exceeded server usage limits
*/
bool IncrementClient(const std::shared_ptr<lacewing::relayserver::client>& client, std::size_t size, bool blasted)
{
	auto cd = ClientDataByClientPtr(client);
	if (cd != clientdata.end())
	{
		(**cd).cur.AddMsg(size);

		if (tcpClientUploadCap && !blasted)
		{
			(**cd).exceeded |= (**cd).cur.bytes > tcpClientUploadCap;
			return !(**cd).exceeded;
		}
	}
	return true;
}
void OnPeerMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	std::shared_ptr<lacewing::relayserver::channel> viachannel, std::shared_ptr<lacewing::relayserver::client> receiverclient,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	serverstats.in.cur.AddMsg(data.size());

	// UDP upload limit is 4/5 of TCP limit; if a TCP limit is set, a UDP one is too
	if (tcpClientUploadCap && blasted && serverstats.out.cur.bytes > totalUploadCap * 4 / 5)
	{
		server.clientmessage_permit(senderclient, viachannel, receiverclient, blasted, subchannel, data, variant, false);
		return;
	}

	// False means it's exceeded TCP limits (if TCP limit is off, this'll always return true)
	if (!IncrementClient(senderclient, data.size(), blasted))
	{
		server.clientmessage_permit(senderclient, viachannel, receiverclient, blasted, subchannel, data, variant, false);
		return;
	}

	serverstats.out.cur.AddMsg(data.size());
	server.clientmessage_permit(senderclient, viachannel, receiverclient, blasted, subchannel, data, variant, true);
}

void OnChannelMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	std::shared_ptr<lacewing::relayserver::channel> channel,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	serverstats.in.cur.AddMsg(data.size());

	// UDP upload limit is 4/5 of TCP limit; if a TCP limit is set, a UDP one is too
	if (tcpClientUploadCap && blasted && serverstats.out.cur.bytes > totalUploadCap * 4 / 5)
	{
		server.channelmessage_permit(senderclient, channel, blasted, subchannel, data, variant, false);
		return;
	}

	// False means it's exceeded TCP limits (if TCP limit is off, this'll always return true)
	if (!IncrementClient(senderclient, data.size(), blasted))
	{
		server.channelmessage_permit(senderclient, channel, blasted, subchannel, data, variant, false);
		return;
	}

	server.channelmessage_permit(senderclient, channel, blasted, subchannel, data, variant, true);
	serverstats.out.cur.AddMulti(channel->clientcount() - 1U, data.size());
}

// Until we have a better general error handler for Lacewing...
extern "C" void always_log(const char* c, ...)
{
	char output[1024];
	va_list v;
	va_start(v, c);
	int numChars = vsprintf_s(output, std::size(output), c, v);
	// always_log should always output valid data
	if (numChars <= 0)
		std::abort();

	std::string_view outputStr(output, numChars);
	if (outputStr.back() == '\n')
		outputStr.remove_suffix(1);
	if (outputStr.back() == '\r')
		outputStr.remove_suffix(1);

	// If this happens, this code needs to be designed to split the log into lines,
	// and output them with lineEnd(false) until last line
	// Currently always_log does not output multiple lines.
	assert(outputStr.find('\n') == std::string_view::npos);

	wchar_t * output_wide = lw_char_to_wchar(output, static_cast<int>(outputStr.size()));
	std::wstring_view outputWideSV(output_wide);
	std::wcout << yellow << L"(AL) "sv << outputWideSV << lineEnd();
	free(output_wide);
	va_end(v);
}

void GenerateFlashPolicy(int port)
{
	lw_string filename = appFolder + L"FlashPlayerPolicy.xml"s;

	// File already exists; just use it
	DWORD policyAttr = GetFileAttributes(filename.c_str());
	if (policyAttr != INVALID_FILE_ATTRIBUTES && !(policyAttr & FILE_ATTRIBUTE_DIRECTORY))
	{
		flashPolicyPath = WideToUTF8(filename);
		return;
	}

	// We write UTF-8 (well, ASCII really), but open filename in UTF-16
	HANDLE forWriting = CreateFile(filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (forWriting == NULL || forWriting == INVALID_HANDLE_VALUE)
	{
		std::wcout << red << L"Flash policy couldn't be created. Opening file \""sv << filename
			<< L"\" for writing in current app folder failed."sv << lineEnd();
		return;
	}

	deleteFlashPolicyAtEndOfApp = true;

	std::stringstream flashPolicy;
	flashPolicy << "<?xml version=\"1.0\"?>\n"sv
		"<!DOCTYPE cross-domain-policy SYSTEM \"/xml/dtds/cross-domain-policy.dtd\">\n"sv
		"<cross-domain-policy>\n"sv
		"\t<site-control permitted-cross-domain-policies=\"master-only\"/>\n"sv
		"\t<allow-access-from domain=\"*\" to-ports=\"843," << port << ",583\" secure=\"false\" />\n"sv
		"</cross-domain-policy>"sv;
	const std::string policyStr = flashPolicy.str();
	if (!WriteFile(forWriting, policyStr.c_str(), (DWORD)policyStr.size(), NULL, NULL))
	{
		std::wcout << red << L"Flash policy couldn't be created. Writing to file "sv << filename << L" failed."sv << lineEnd();
		CloseHandle(forWriting);
		DeleteFile(filename.c_str());
		return;
	}

	CloseHandle(forWriting);
	flashPolicyPath = WideToUTF8(filename);
}

// This CloseHandler is spawned by OS in a separate thread to main(), so output will be unsynced,
// making it particularly messy in startup when you're waiting for user input and get a Ctrl-C instead.
// We don't write to std::wcout here, unless we know server is running - which is when globalpump is set.
BOOL WINAPI CloseHandler(DWORD ctrlType)
{
	// This is used for cold restarts, and sometimes for mid-way statistics like in ping
	if (ctrlType == CTRL_BREAK_EVENT)
	{
		if (globalpump)
			statsDump = true;
		return TRUE;
	}

	// Close, logoff and shutdown events will terminate app when this handler returns
	const bool appDiesAfterReturn = ctrlType != CTRL_C_EVENT;

	// Ctrl-C is traditional exit-console event. Close is user pressing close on window.
	// Note that logoff and shutdown is not run for most consoles, only for services:
	// https://stackoverflow.com/a/74376684
	if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT ||
		ctrlType == CTRL_LOGOFF_EVENT || ctrlType == CTRL_SHUTDOWN_EVENT)
	{
		// Don't wait for user to press a key to end app (if we were going to)
		if (appDiesAfterReturn)
			requestUserInput = false;

		// Only trigger once
		if (!shutdowned)
		{
			shutdowned = true;

			if (globalpump)
			{
				std::wcout << red << L"Got a close signal, ending app."sv << lineEnd();
				globalpump->post_eventloop_exit();
			}
		}

		if (appDiesAfterReturn)
		{
			while (globalpump)
				Sleep(25);
		}
		
		return TRUE;
	}

	// Other handler types are reserved
	return FALSE;
}

// Returns true if std::wcin has a character to report. Uses OS-specific methods.
bool cinInputPending()
{
	// _kbhit() is MS specific for seeing if cin has data, there is no cross-compatible C++ way
	// Internally, it delegates to Windows-specific PeekConsoleInputEvents()
	return _kbhit();
}


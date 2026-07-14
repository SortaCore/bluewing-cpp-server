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
#include "LinuxConsole.hpp"

// Includes all global variables and headers that both Windows wchar_t and non-Windows char use.
#include "GenericConsole.hpp"

// Reprints the time and statistics line. Called by lineEnd() and when stats timer ticks.
static void ReprintStatisticsLine()
{
	// We don't maintain a stats line if we're not writing to a console.
	// We also should not print if the server is pre-startup or currently shutting down.
	if (!isConsoleOutput || lastTimeAndStats.empty())
		return;

	std::cout << gray << lastTimeAndStats << std::flush;
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
		std::cout << u8'\n';
		if (!wrp.reprintStatsLine)
			std::cout << timeBuffer;
		return str;
	}
		
	// Erase current line to end, then move to next line
	std::cout << u8"\x1b[0K\n"sv;

	if (wrp.reprintStatsLine)
		ReprintStatisticsLine();
	else // prepare for another line
		std::cout << timeBuffer;
	return str;
}

// Checks if a port text input by a user is valid or re-used elsewhere.
static void CheckPort(const lw_char * portStr, lw_ui16 * writeTo, std::function<void()> errInv)
{
	const std::uint32_t portNum = static_cast<std::uint32_t>(std::strtoul(portStr, nullptr, 10));

	// Check port is in valid range. Port 843 is used for Flash policy.
	if (portNum == 843 || portNum == 0 || portNum > std::numeric_limits<lw_ui16>::max())
	{
		std::cout << red;
		errInv();
		std::cout << u8" had invalid port number "sv << portStr << u8'.' << lineEnd();
		return;
	}
	*writeTo = (lw_ui16)portNum;

	// Check port does not match others
	if ((writeTo != &mainPort && *writeTo == mainPort) ||
		(writeTo != &websocketNonSecurePort && *writeTo == websocketNonSecurePort) ||
		(writeTo != &websocketSecurePort && *writeTo == websocketSecurePort))
	{
		errInv();
		std::cout << u8" port number "sv << portStr << u8" was reused in several ports."sv << lineEnd();
	}
}
static lw_string GetConsoleLine(bool password = false)
{
	assert(isConsoleOutput);

	// Due to outputting to file, running under debugger, or other reasons, we don't prompt user
	if (!requestUserInput)
	{
#ifdef _DEBUG
		std::cout << u8"(prompting disabled)\n"sv;
#endif
		return lw_string();
	}

	// Set console color for user's response text
	std::cout << userresponsecolor;

	// Turn off echo of input to output
	std::cout << u8"\033 7"sv;
	termios oldt, newt;
	if (password)
	{
		tcgetattr(STDIN_FILENO, &oldt);
		newt = oldt;
		newt.c_lflag &= ~ECHO;
		tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	}

	lw_string consoleInputLine;
	std::getline(std::cin, consoleInputLine);

	// User aborted reading input e.g. Ctrl-C
	if (shutdowned || std::cin.fail())
		return lw_string();

	// restore cursor pos to previous line if no input to show
	if (consoleInputLine.empty())
		std::cout << u8"\033 8"sv;

	// restore echo and generate random asterisk for password
	if (password)
	{
		tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		std::cout << lw_string(consoleInputLine.empty() ? 10 + (rand() % 20) : consoleInputLine.size(), u8'*') << u8'\n';
	}
	else if (consoleInputLine.empty())
		std::cout << u8"(empty input)\n"sv;
	return consoleInputLine;
}
// Looks for matching default TLS cert files and uses the first to match
static void GuessCertPath()
{
	if (!wsFullChainPath.empty())
		return;

	// Search app directory for matching files

	if (lw_file_exists("./fullchain.pem") && lw_file_exists("./privkey.pem"))
	{
		wsPrivKeyPath = "./privkey.pem"s;
		wsFullChainPath = "./fullchain.pem"s;
		std::cout << green << u8"Auto-set cert files to privkey.pem and fullchain.pem from current directory."sv << lineEnd();
		return;
	}
	// Not found at all - if websocket insecure was on, they probably want a secure cert
	if (websocketNonSecurePort)
	{
		std::cout << yellow << u8"Couldn't auto-find TLS certficate files - expecting "sv;

		std::cout << u8"\"fullchain.pem\" and \"privkey.pem\" in app folder."sv << lineEnd();
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
	if (shutdowned || (requestUserInput && std::cin.fail()))
		return false;

	lw_string consoleInputLine;
	if (requestUserInput && !requireCert)
		std::cout << userpromptcolor << u8"Enter a "sv << req << u8" port (leave empty for default " << defaultVal << u8"):\n"sv;
	// else cert is required for this port: guess cert
	else
	{
		GuessCertPath();

		if (!requestUserInput)
		{
			*writeTo = defaultVal;
			return true;
		}
		std::cout << userpromptcolor << u8"Enter a "sv << req << u8" port (leave empty for default "sv << defaultVal <<
			u8", or pass 0 to disable secure websocket):\n"sv;
	}
	consoleInputLine = GetConsoleLine();

	bool good = true;
	if (consoleInputLine.empty())
	{
		// User pressed Ctrl-C during input
		if (shutdowned || std::cin.fail())
			return false;

		*writeTo = defaultVal;
	}
	else
	{
		CheckPort(consoleInputLine.c_str(), writeTo, [&]() {
			std::cout << u8"Invalid input: "sv << req;
			good = false;
		});
	}
	// Cert is required for this port, and we don't have cmdline arg
	if (good && requireCert && *writeTo != 0)
	{
		if (wsFullChainPath.empty())
		{
			std::cout << userpromptcolor << u8"Enter a path to TLS certificate file (combined PFX or full chain PEM), or leave empty to disable websocket secure hosting:\n"sv;
			consoleInputLine = GetConsoleLine();
			if (consoleInputLine.empty())
			{
				std::cout << green << u8"Left empty. Will continue webserver with just insecure websocket."sv << lineEnd();
				websocketSecurePort = 0;
				return true;
			}
			wsFullChainPath = consoleInputLine;
		}
		if (wsPrivKeyPath.empty())
		{
			std::cout << userpromptcolor << u8"Enter a path to SSL priv key certificate file (PFX or PEM), or leave empty if part of chain file:\n"sv;
			consoleInputLine = GetConsoleLine();
			wsPrivKeyPath = consoleInputLine.empty() ? wsFullChainPath : consoleInputLine;
		}

		if (wsPassPhrase.empty())
		{
			std::cout << userpromptcolor << u8"Enter a password to the certificate file(s), or leave empty if none:\n"sv;
			consoleInputLine = GetConsoleLine(true);
			wsPassPhrase = consoleInputLine;
		}
	}

	return good;
}

// Converts time_t to full date-time representation based on local date format
lw_string fulltimetostring(std::time_t timepoint)
{
	lw_string buffer(100, u8'\0');
	std::tm timeinfo = { 0 };
	if (localtime_r(&timepoint, &timeinfo))
		std::strftime(buffer.data(), buffer.size(), u8"%I:%M:%S%p %x", &timeinfo);
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
	std::cout << green << std::setw(70) << std::setfill(u8'=') << u8""sv << std::setw(0) << std::setfill(u8' ') << lineEnd(false);
	if (endOfApp)
		std::cout << u8"Program completed. Total statistics:"sv << lineEnd(false);
	else
		std::cout << u8"Manual statistics request. Statistics since start of server:" << lineEnd(false);
	
	const std::time_t curTime = time(NULL);
	const std::uint64_t secondsUp = std::max<std::uint64_t>(1, (std::uint64_t)std::ceil(difftime(curTime, startTime)));
	// Division is floor by default
	const std::uint64_t hours = secondsUp / (60ULL * 60ULL), minutes = (secondsUp / 60ULL) % 60ULL, seconds = secondsUp % 60ULL;
	std::cout
		<< u8"     Start time: "sv << fulltimetostring(startTime) << u8". "sv << lineEnd(false)
		<< (endOfApp ? u8"       End"sv : u8"   Current"sv) << u8" time: "sv << fulltimetostring(curTime) << u8". "sv << lineEnd(false)
		<< u8"    Hosting for: "sv << hours << u8" hrs, "sv << minutes << u8" mins, "sv << seconds << u8" seconds ("sv << secondsUp << u8" seconds total)."sv << lineEnd(false)
		<< u8"   Max in 1 sec: "sv << serverstats.in.highestSec.bytes << u8" bytes in, "sv << serverstats.out.highestSec.bytes << u8" bytes out."sv << lineEnd(false)
		<< u8"                 "sv << serverstats.in.highestSec.msg << u8" msgs in, "sv << serverstats.out.highestSec.msg << u8" msgs out (may be diff seconds)."sv << lineEnd(false)
		<< u8"    Avg per sec: "sv << (serverstats.in.total.bytes / secondsUp) << u8" bytes in, "sv << (serverstats.out.total.bytes / secondsUp) << u8" bytes out."sv << lineEnd(false)
		<< u8"                 "sv << (serverstats.in.total.msg / secondsUp) << u8" msgs in, "sv << (serverstats.out.total.msg / secondsUp) << u8" msgs out."sv << lineEnd(false)
		<< u8"          Total: "sv << serverstats.in.total.bytes << u8" bytes in, "sv << serverstats.out.total.bytes << u8" bytes out."sv << lineEnd(false)
		<< u8"                 "sv << serverstats.in.total.msg << u8" msgs in, "sv << serverstats.out.total.msg << u8" msgs out."sv << lineEnd(false)
		<< u8"    Max clients: "sv << serverstats.maxClients << u8", max channels: "sv << serverstats.maxChannels << u8'.' << lineEnd(false);
	if (endOfApp)
		std::cout << u8"Current clients: "sv << globalserver->clientcount() << u8", current channels: "sv << globalserver->channelcount() << u8'.' << lineEnd(false);
	std::cout
		<< std::setw(70) << std::setfill(u8'=') << u8""sv << std::setw(0) << std::setfill(u8' ') << lineEnd(!endOfApp);
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
int main(const int argcf, lw_char* argv[])
{
	const std::size_t argc = static_cast<std::size_t>(argcf);
	// If true, cmdline is set to require admin
	bool requireAdmin = false;
	
	// GDB sometimes takes a while to link to stdout
#ifdef _DEBUG
	std::cout << std::flush;
	std::cerr << std::flush;
	std::this_thread::sleep_for(3s);
#endif

	// Handle user and OS interrupts.
	// 
	// This is the other entry point from OS -> program. OS will pick a thread that has a handler
	// to call CloseHandler on. We only use one thread in this app.
	// 
	// Registering no handler will result in default OS handling behavior, which may be
	// an instant app terminate, a terminate after dumping RAM to a file in a system folder,
	// or letting program continue as normal.
	// Returning from some signal handlers will result in the signal being called again
	// with default handler, so CloseHandler stalls to allow main thread to exit cleanly
	// when it can.
	// 
	// All but SIGKILL and SIGSTOP can be intercepted.
	struct sigaction act = { };
	act.sa_handler = CloseHandler;
	sigemptyset(&act.sa_mask);

	// SIGINT is a more "friendly" signal caused by Ctrl-C. It is also raised if your code hits a debugger-set breakpoint.
	sigaddset(&act.sa_mask, SIGINT);

	// SIGQUIT is caused by Ctrl-\, which closes your app and dumps the running state,
	// basically requesting exit with a dump of all files your app is currently using.
	// Returning from handler is instant app close.
	sigaddset(&act.sa_mask, SIGQUIT);

	// SIGABRT is caused by abort(), generally raised by internal CRT code for serious issues such as corrupt heap.
	// Returning from handler usually causes abort() to reset the handler to OS default and raise it again,
	// which causes instant app close.
	sigaddset(&act.sa_mask, SIGABRT);

	// These are caused by bad memory access (SIGSEGV), unaligned memory access (SIGBUS), or illegal CPU instructions (SIGILL).
	// Returning from handler is likely going to crash the app and cause instant app close.
	sigaddset(&act.sa_mask, SIGILL);
	sigaddset(&act.sa_mask, SIGSEGV);
	sigaddset(&act.sa_mask, SIGBUS);

	// SIGFPE is floating-point exception, e.g. dividing by zero, float overflow, etc. It can be ignored,
	// although it leads the running code in undefined state, so we close down in response.
	// Returning from handler is instant app close.
	//sigaddset(&act.sa_mask, SIGFPE);

	// SIGPIPE is writing to a pipe that no longer exists.
	// Returning from handler is instant app close.
	sigaddset(&act.sa_mask, SIGPIPE);

	// SIGTERM is when OS is requesting app to instantly close. It is "gentle" compared to SIGKILL,
	// which is not raised in processes and cannot be intercepted.
	// Returning from handler is instant app close.
	// On system shutdown, SIGTERM is sent; apps have usually 5s to close down before SIGKILL.
	sigaddset(&act.sa_mask, SIGTERM);
	if (sigaction(SIGINT, &act, NULL))
	{
		std::cout << u8"Could not set console close handler, error "sv << errno << u8".\n"sv;
		return ENOTSUP;
	}

#ifndef _DEBUG
	// We don't use C-style printf(), so desync C++ console output (std::cout) and C (printf, puts).
	// It's unclear whether std::cout or printf is faster; and some say std::cout is faster
	// only with a fast locale.
	// Since Bluewing currently requires C++17, for use of std::string_view and std::shared_ptr,
	// we'll stick to C++ console.
	std::ios_base::sync_with_stdio(false);
#endif // !_DEBUG


	// Update timeBuffer for startup output
	OnTimerTick(nullptr);

	// Get app directory that app is running from, by getting running app full path.
	// argv[0] may contain relative path, so it shouldn't be relied on.
	{
		lw_string filenameBuf;
		filenameBuf.resize(256);
		// Get full path of app, including filename + ext.
		for (ssize_t pathLen; true;)
		{
			pathLen = ::readlink("/proc/self/exe", filenameBuf.data(), filenameBuf.size());
			// Sometimes, the OS hasn't made the symlink yet, and returns nothing. Sleep until it's ready.
			if (pathLen == 0)
			{
				std::this_thread::sleep_for(50ms);
				continue;
			}
			if (pathLen == -1)
			{
				std::cout << u8"Looking up current app folder failed 2, error "sv << errno << u8".\n"sv;
				return EINVAL;
			}
			// Enough written
			if ((size_t)pathLen < filenameBuf.size())
			{
				filenameBuf.resize(pathLen);
				break;
			}

			// Extend the buffer to next power of 2, try again
			filenameBuf.resize(filenameBuf.size() << 1);
		}

		// Trim to last slash.
		const std::size_t lastSlash = filenameBuf.find_last_of(u8"\\/"sv);
		if (lastSlash == lw_string::npos)
		{
			std::cout << red << u8"Current app path \""sv << filenameBuf << u8"\" made no sense."sv << lineEnd();
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
					std::cout << u8"Invalid cmdline: " << argv[argCIdxName] << u8" had no following value.\n"sv;
					return (bad = true);
				}

				CheckPort(argv[argCIdxName + 1], writeTo, [&]() {
					std::cout << u8"Invalid cmdline: "sv << argv[argCIdxName];
					bad = true;
					});
				return !bad;
			};
			const auto setpath = [&](std::size_t argCIdxName, std::string* writeTo) {
				if (argCIdxName + 1 >= argc)
				{
					std::cout << u8"Invalid cmdline: "sv << argv[argCIdxName] << u8" had no following value.\n"sv;
					return (bad = true);
				}

				// If flash policy path is specified, it must exist
				if (!lw_file_exists(argv[argCIdxName + 1]))
				{
					std::cout << u8"Invalid cmdline: "sv << argv[argCIdxName] << u8" had invalid path \"" << argv[argCIdxName + 1] << u8"\".\n"sv;
					return (bad = true);
				}
				*writeTo = argv[argCIdxName + 1];
				// PFX may hold both priv key and full chain, but should only be passed once, as priv key
				if (writeTo == &wsFullChainPath && lw_u8str_icmp(*writeTo, wsPrivKeyPath))
				{
					std::cout << u8"Invalid cmdline: \""sv << argv[argCIdxName] << u8"\" cert path \""sv
						<< argv[argCIdxName + 1] << u8"\" was reused for both fullchain and priv key. "
						"Only pass it for priv key if you're using a PFX with both.\n"sv;
					return (bad = true);
				}
				if (writeTo == &flashPolicyPath && (lw_u8str_icmp(*writeTo, wsFullChainPath) || lw_u8str_icmp(*writeTo, wsPrivKeyPath)))
				{
					std::cout << u8"Invalid cmdline: \""sv << argv[argCIdxName] << u8"\" policy path \""sv
						<< argv[argCIdxName + 1] << u8"\" was reused for a websocket cert path.\n"sv;
					return (bad = true);
				}

				return !bad;
			};
			// Assume the first argv[0] is app path, and skip it
			// otherwise read all arguments in key-value pairs, or as keys by themselves
			for (std::size_t i = 1; i < argc;)
			{
				// Skip past commandline - or / precursor
				if (argv[i][0] == u8'/' || argv[i][0] == u8'-')
					++argv[i];

				// These only edit the same things
				if ((!strcasecmp(argv[i], u8"mainPort") && setport(i, &mainPort)) ||
					(!strcasecmp(argv[i], u8"wsPort") && setport(i, &websocketNonSecurePort)) ||
					(!strcasecmp(argv[i], u8"wssPort") && setport(i, &websocketSecurePort)) ||
					(!strcasecmp(argv[i], u8"certFullChainPath") && setpath(i, &wsFullChainPath)) ||
					(!strcasecmp(argv[i], u8"certPrivKeyPath") && setpath(i, &wsPrivKeyPath)))
				{
					i += 2;
					continue;
				}
				// Flash policy set: presumably we want flash enabled
				if (!strcasecmp(argv[i], u8"flashPolicyPath") && setpath(i, &flashPolicyPath))
				{
					if (flashEnabled)
						std::cout << u8"Warning: cmdline enableFlash does not need passing if you pass the flash policy path.\n"sv;
					flashEnabled = true;
					i += 2;
					continue;
				}
				// Flash is enabled: assume it is to be generated, or read from app directory
				if (!strcasecmp(argv[i], u8"enableFlash"))
				{
					// They also passed flash policy, so complain
					if (!flashPolicyPath.empty())
						std::cout << u8"Warning: cmdline "sv << argv[i] << u8" does not need passing if you set the policy path.\n"sv;
					flashEnabled = true;
					++i;
					continue;
				}
				// If this is true, expects the server program to be run under admin privileges,
				// which is necessary for ICMP raw sockets (used for UDP error replies),
				// and for privileged hosting (hosting on a port number below 1024)
				if (!strcasecmp(argv[i], u8"requireAdmin"))
				{
					requireAdmin = true;
					++i;
					continue;
				}
				// If this is true, turns off the statistics line and the title bar updates.
				// The ability to use cin for statistics, or send report messages, is still usable.
				if (!strcasecmp(argv[i], u8"noRegularOutput"))
				{
					regularOutputEnabled = false;
					++i;
					continue;
				}
				// Sets the TLS certificate private password; note the server does not explicitly store
				// this securely, it depends on SChannel or OpenSSL's storage.
				if (!strcasecmp(argv[i], u8"certPassPhrase"))
				{
					if (i + 1 >= argc)
					{
						std::cout << u8"Invalid cmdline: "sv << argv[i] << u8" had no following value.\n"sv;
						bad = true;
						break;
					}
					wsPassPhrase = argv[i + 1];
					if (wsPassPhrase[0] == u8'"')
					{
						wsPassPhrase.erase(0);
						wsPassPhrase.erase(wsPassPhrase.cend());
					}
					i += 2;
					continue;
				}
				if (!strcasecmp(argv[i], u8"welcomeMsg"))
				{
					if (i + 1 >= argc)
					{
						std::cout << u8"Invalid cmdline: "sv << argv[i] << u8" had no following value.\n"sv;
						bad = true;
						break;
					}
					welcomeMessage = argv[i + 1];
					i += 2;
					continue;
				}
				if (!strcasecmp(argv[i], u8"tcpClientUploadCap") || !strcasecmp(argv[i], u8"totalUploadCap"))
				{
					if (i + 1 >= argc)
					{
						std::cout << u8"Invalid cmdline: "sv << argv[i] << u8" had no following value.\n"sv;
						bad = true;
						break;
					}
					const std::uint32_t capBytes = static_cast<std::uint32_t>(std::strtoul(argv[i + 1], nullptr, 10));
					if (capBytes < 0)
					{
						std::cout << u8"Invalid cmdline: "sv << argv[i] << u8" had invalid value "sv << capBytes << u8" bytes.\n"sv;
						bad = true;
						break;
					}
					if (!strcasecmp(argv[i], "tcpClientUploadCap"))
						tcpClientUploadCap = (std::size_t)capBytes;
					else
						totalUploadCap = (std::size_t)capBytes;
					i += 2;
					continue;
				}
				// Give help
				if (!strcasecmp(argv[i], u8"?") || !strcasecmp(argv[i], u8"help"))
				{
					std::cout << u8"==== " PROJECT_NAME " "sv;
#					ifdef _DEBUG
					std::cout << u8"debug"sv;
#					else // !_DEBUG
					std::cout << u8"release"sv;
#					endif // _DEBUG
					std::cout << u8" build "sv << lacewing::relayserver::buildnum << u8" cmdline options ====\n"
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

				std::cout << u8"Invalid cmdline: "sv << argv[i] << u8" was not recognised.\n"sv;
				bad = true;
				break;
			}
		}

		if (bad)
			goto cleanup;
	}

	// Backup current console config for restoring
	// A TTY is a normal console; if this is false, not console output (e.g. redirected stdout to file)
	isConsoleOutput = regularOutputEnabled && isatty(fileno(stdout));

	if (isConsoleOutput)
	{
		// We restore origTerminalSettings if isConsoleOutput is true, so it must be valid.
		if (tcgetattr(STDIN_FILENO, &origTerminalSettings) != 0)
		{
			std::cout << red << u8"Failed to get terminal settings (error "sv << errno << u8"). Aborting server start."sv << lineEnd();
			return -1;
		}

		// Same as outputting gray but without time buffer
		std::cout << u8"\033[37m";
	}

	// Check for admin membership, required for ICMP raw sockets, which are used for UDP error replies
	// Blue Server does not *require* ICMP replies though; it will silently ignore bad UDP (e.g. from an unrecognised IP)
	{
		// Linux-based OSes also require net bind service permission if targeting ports below 1024.
		// You can enable both of these by running server under root user, or by adding the perm:
		// $ setcap 'cap_net_bind_service,cap_net_raw=+ep' /path/to/bluewing-cpp-server
		// Noteably, the websocket server ports are by default port 80 and 443, flash policy 843.
		// This perm check will assume admin permissions if it cannot check.
		bool isAdmin = true;
#if __has_include(<sys/capabilities.h>)
		const cap_t current = cap_get_proc();
		if (current == NULL)
		{
			std::cout << red << u8"Warning: Failed to get process capabilities (error "sv << errno << u8"). Assuming raw socket + net bind capabilities are granted.\n"sv;
			cap_flag_value_t on;
			if (cap_get_flag(current, CAP_NET_BIND_SERVICE, CAP_PERMITTED, &on) != 0) {
				std::cout << red << u8"Warning: Failed to check cap_net_bind_service value (error "sv << errno << u8"). Assuming it is granted.\n"sv;
			}
			isAdmin = on == 1;
			if (cap_get_flag(current, CAP_NET_RAW, CAP_PERMITTED, &on) != 0) {
				std::cout << red << u8"Warning: Failed to check cap_net_raw capability (error "sv << errno << u8"). Assuming it is granted.\n"sv;
			}
			isAdmin &= on == 1;
		}
#else // __has_include 0
		std::cout << red << u8"Warning: Server was built without libcap-dev. Checking for raw socket/port bind privileges is not possible. Assuming they are granted.\n"sv;
#endif // __has_include

		if (!isAdmin)
		{
			if (requireAdmin)
			{
				std::cout << red << u8"Server is set by command-line to require admin, and is not running as admin. Server start aborted.\n"sv;
				goto cleanup;
			}
			std::cout << red << u8"Warning: server is not running with admin privileges. Resetting UDP connections with ICMP will not be possible.\n"sv;
		}
	}

	// If console output, and no cmd args were passed at all, ask user for input
	if (argc <= 1)
	{
		if (!GetPortFromInput(u8"main"sv, &mainPort, false, 6121) ||
			!GetPortFromInput(u8"WebSocket insecure"sv, &websocketNonSecurePort, false, 80) ||
			!GetPortFromInput(u8"WebSocket secure"sv, &websocketSecurePort, true, 443))
		{
			goto cleanup;
		}
		if (welcomeMessage.empty() && requestUserInput)
		{
			std::cout << userpromptcolor << u8"Enter a welcome message, or leave blank for the default message with server build:\n"sv;
			welcomeMessage = GetConsoleLine();
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
				std::cout << red << u8"Server was passed secure port but no certificate paths.\n"sv;
				goto cleanup;
			}
		}
	}

	// Block some IPs by default
	//misbehavingIPList.emplace_back(MisbehavingIPEntry("127.0.0.1"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, std::string_view(), laceclock::now() + 24h));
	misbehavingIPList.emplace_back(MisbehavingIPEntry("176.59.131.111"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, std::string_view(), laceclock::now() + 24h));

	// Stop echoing std::cin keypresses to std::cout display, and disable line buffering.
	// Line buffering is where std::cin will buffer until Enter, resulting in no key registering,
	// including in getch().
	// This is referred to on Linux as a "cooked" or "canonical" mode.
	// Disabling it causes any character to be put straight into std::cin, without buffering.
	// This allows various "is input pending" functions to work on single keypress.
	if (isConsoleOutput)
	{
		struct termios curTerminalSettings = origTerminalSettings;
		curTerminalSettings.c_lflag &= ~(ECHO | ICANON);

		// In Linux, Ctrl-Z results in SIGTSTP signal being raised.
		// It is an old design to allow single-task terminal to swap between multiple foreground programs,
		// by suspending with Ctrl-Z (raising SIGTSP), and resuming with fg command (raising SIGCONT).
		// 
		// As Bluewing is a real-time server, that's a bad idea.
		// Having a SIGTSP signal handler won't stop the enclosing terminal from freezing the server
		// anyway, so we instead tell terminal to disable Ctrl-Z handling and treat Ctrl-Z as a
		// normal std::cin key, here.
		// Ctrl-\ results in SIGQUIT, which is intended for app dump of all live data + exit.
		// We prevent that as well.
		curTerminalSettings.c_cc[VSUSP] =
			curTerminalSettings.c_cc[VQUIT] = _POSIX_VDISABLE;

		// A success return may be only partial success. Confirm all were set as we wanted.
		if (tcsetattr(STDIN_FILENO, TCSANOW, &curTerminalSettings) != 0 ||
			tcgetattr(STDIN_FILENO, &curTerminalSettings) != 0 ||
			curTerminalSettings.c_cc[VSUSP] != _POSIX_VDISABLE ||
			curTerminalSettings.c_cc[VQUIT] != _POSIX_VDISABLE ||
			(curTerminalSettings.c_lflag & (ECHO | ICANON)) != 0)
		{
			std::cout << red << u8"Warning: Failed to set stdin terminal settings (error "sv << errno << u8"). "
				"Server may malfunction if user leaves terminal or a special keybind is used."sv << lineEnd();
		}
	}

	// User input is not echoed to output screen anymore, so we don't need cin and cout sync'd
	std::cin.tie(nullptr);

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
	std::cout << green << u8"Host started. Port "sv << mainPort << u8", build "sv << globalserver->buildnum << u8". "sv
		<< (flashEnabled ? u8"Flash policy hosting on TCP port 843"sv : u8"Flash not hosting"sv) << u8'.' << lineEnd();

	// For loading from Windows certificate store (certmgr.msc), use e.g. websocket->load_sys_cert("Root", "yourdomain.com", "LocalMachine")
	if (websocketSecurePort &&
		!globalserver->websocket->load_cert_file(wsFullChainPath.c_str(), wsPrivKeyPath.c_str(), wsPassPhrase.c_str()))
	{
		if (wsFullChainPath == wsPrivKeyPath)
		{
			std::cout << red << u8"Found but couldn't load TLS certificate file \""sv << wsFullChainPath
				<< u8"\". Aborting server start."sv << lineEnd();
		}
		else
		{
			std::cout << red << u8"Found but couldn't load TLS certificate files \""sv << wsFullChainPath << u8"\", \""sv
				<< wsPrivKeyPath << u8"\". Aborting server start."sv << lineEnd();
		}
		goto cleanup;
	}

	if (websocketNonSecurePort || websocketSecurePort)
	{
		std::cout << green << u8"WebSocket hosting. Port "sv;
		if (websocketNonSecurePort)
			std::cout << websocketNonSecurePort << u8" (non-secure, ws://xx)"sv;
		if (websocketNonSecurePort && websocketSecurePort)
			std::cout << u8" and port "sv;
		if (websocketSecurePort)
			std::cout << websocketSecurePort << u8" (secure, wss://xx)"sv;
		std::cout << u8'.' << lineEnd(false);
	}

	// Enable the user's preferred date-time and large number format, using "" locale,
	// instead of the "C" default.
	// This sets big numbers to have thousand separators in statistics, and so on.
	// We don't do it earlier as ports will be displayed wrong (e.g. as "6,121").
	std::cout.imbue(std::locale(std::string()));
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
		std::cout << u8"\x1b[?25l"sv;

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
			std::cout << red << u8"Error occurred in pump: "sv << error->tostring() << lineEnd();
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
		remove(flashPolicyPath.c_str());
	}


	// If we inited properly, show the end app stats
	if (goodInit)
		PrintTotalStatistics(true);

	// Restore input-output stream sync
	std::cin.tie(&std::cout);

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
			std::cin.clear();
			while (cinInputPending())
				std::cin.get();
			std::cout << std::flush;


		}
		
		// Erase current line to end, then set console cursor visible
		std::cout << u8"\x1b[0K\x1b[?25h"sv;
		std::cout << u8'\r';

		// Read one character
		if (requestUserInput)
		{
			std::cout << gray << u8"Press any key to exit.\n"sv << std::flush;
			std::cin.get();
		}

		// Restore terminal settings
		tcsetattr(STDIN_FILENO, TCSANOW, &origTerminalSettings);
	}
	std::cout << std::flush;

	return !goodInit;
}

void UpdateTitle(std::size_t clientCount)
{
	// We can't set title if we don't have a console
	if (!isConsoleOutput)
		return;
	std::size_t channelCount = globalserver->channelcount();
	lw_char name[128];
	sprintf(name, u8"Bluewing C++ Server - %zu client%s connected in %zu channel%s",
		clientCount, clientCount == 1 ? u8"" : u8"s",
		channelCount, channelCount == 1 ? u8"" : u8"s");
	std::cout << u8"\033]0;"sv << name << "\x1B\x5C"sv;

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
	const std::string_view addr = client->getaddress();
	const lw_string addrW(client->getaddress());

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
				std::cout << yellow << u8"Blocked connection attempt from IP "sv << addrW << u8", banned due to "sv
					<< entry->reason << u8'.' << lineEnd();
			}
			entry->nextLogLine = now + 1min;
			return server.connect_response(client, entry->reason.c_str());
		}
	}

	// Allow connection
	server.connect_response(client, std::string_view());
	UpdateTitle(server.clientcount());

	std::cout << green << u8"New client ID " << client->id() << u8", IP "sv << addrW << u8" connected."sv << lineEnd();
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
	const std::string_view addr = client->getaddress();

	// A client that is not Relay will not have called OnConnect, so we won't have a data for it
	const auto cd = ClientDataByClientPtr(client);
	std::cout << green << u8"Client ID "sv << client->id() << u8", name "sv << name << u8", IP "sv << addr << u8" disconnected."sv;
	if (cd != clientdata.cend())
		std::cout << u8" Uploaded "sv << (**cd).total.bytes << u8" bytes in "sv << (**cd).total.msg << u8" msgs total."sv;
	std::cout << lineEnd();

	// client.istrusted() indicates whether the client sent invalid Bluewing messages, and is getting kicked
	// for violations, or whether the client is disconnecting of its own accord.
	if (!client->istrusted() && !IsIPTrusted(addr))
	{
		const auto entry = std::find_if(misbehavingIPList.begin(), misbehavingIPList.end(), [&](const MisbehavingIPEntry & b) { return b.ip == addr; });
		if (entry == misbehavingIPList.end())
		{
			std::cout << yellow << u8"Due to malformed protocol usage, created a IP ban entry."sv << lineEnd();
			AddMisbehavingIPEntry(**cd, addr, "Broken Lacewing protocol", laceclock::now() + 30min);
		}
		else
		{
			std::cout << yellow << u8"Due to malformed protocol usage, increased their ban likelihood."sv << lineEnd();
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
	if (localtime_r(&rawtime, &timeinfo))
		std::strftime(timeBuffer, std::size(timeBuffer), u8"%T | ", &timeinfo);

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
		lastTimeAndStatsSS << u8"Last sec received "sv << serverstats.in.lastSec.msg << u8" messages ("sv << serverstats.in.lastSec.bytes
			<< u8" bytes), forwarded "sv << serverstats.out.lastSec.msg << u8" ("sv << serverstats.out.lastSec.bytes << u8" bytes).\r"sv;
		lastTimeAndStats = lastTimeAndStatsSS.str();
		lastTimeAndStatsSS.clear();
		lastTimeAndStatsSS.str(lw_string());
		ReprintStatisticsLine();
	}

	// If user has pressed keys on console
	if (cinInputPending())
	{
		int cinKey = std::cin.get();
		// Space key: write statistics
		if (cinKey == u8' ')
			statsDump = true;
		// User pressed Ctrl-Z for SIGTSTP on Linux, which normally sends 0x1F & Z, displays as ^Z.
		// or User pressed Ctrl-\ for SIGQUIT.
		else if (cinKey == (0x1F & origTerminalSettings.c_cc[VSUSP]) ||
			cinKey == (0x1F & origTerminalSettings.c_cc[VQUIT]))
		{
			statsDump = true;
		}
		else // Unrecognised, do a warning beep
			std::cout << u8'\a';
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
			const std::string_view addr = cliData->client->getaddress();

			if (IsIPTrusted(addr))
				continue;

			std::string banReason = "You have been banned for heavy TCP usage."s + contactMsg;
			const auto banEntry = std::find_if(misbehavingIPList.begin(), misbehavingIPList.end(),
				[&](const MisbehavingIPEntry& b) { return b.ip == addr; });
			if (banEntry == misbehavingIPList.end())
				AddMisbehavingIPEntry(*cliData, addr, banReason, laceclock::now() + 1h);
			else
				++banEntry->disconnects;

			std::cout << red << u8"Client ID "sv << cliData->client->id() << u8", IP "sv << addr <<
				u8" dropped for heavy TCP upload ("sv << cliData->cur.bytes << u8" bytes in "sv << cliData->cur.msg << u8" msgs)"sv << lineEnd();
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
	std::cout << red << u8"Error occured: "sv << err << u8". Execution continues."sv << lineEnd();
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

		std::cout << gray << u8"Message from client ID "sv << senderclient->id() << u8", name "sv << name
			<< u8':' << lineEnd(false) << data << lineEnd(false)
			<< u8"blasted = "sv << (blasted ? u8"yes"sv : u8"no"sv)
			<< u8", subchannel = "sv << subchannel << u8", variant = "sv << variant
			<< u8'.' << lineEnd();
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
		const std::string_view addr = senderclient->getaddress();
		std::cout << red << u8"Dropped server message from IP "sv << addr << u8", invalid type."sv << lineEnd();
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
		const std::string_view addr = senderclient->getaddress();

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
					<< "Start time: "sv << fulltimetostring(startTime) << ". Current time: "sv << fulltimetostring(curTime) << ".\n"sv
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

	std::cout << gray << u8"Message from client ID "sv << senderclient->id()
		<< u8", name "sv << name << u8':' << lineEnd(false)
		<< data << lineEnd();
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
	int numChars = vsprintf(output, c, v);
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

	std::cout << yellow << u8"(AL) "sv << outputStr << lineEnd();
	va_end(v);
}

void GenerateFlashPolicy(int port)
{
	lw_string filename = appFolder + u8"FlashPlayerPolicy.xml"s;
	// File already exists; just use it
	struct stat buffer;
	if (::stat(filename.c_str(), &buffer) == 0)
	{
		flashPolicyPath = filename;
		return;
	}

	lw_fstream forWriting(filename, std::ios::out | std::ios::binary);
	//FILE* forWriting = fopen(filename.c_str(), "wb");
	if (forWriting.bad())
	{
		std::cout << u8"Flash policy couldn't be created. Opening file \""sv << filename << u8"\" for writing in current app folder failed.\n"sv;
		return;
	}

	deleteFlashPolicyAtEndOfApp = true;

	forWriting << "<?xml version=\"1.0\"?>\n"
		"<!DOCTYPE cross-domain-policy SYSTEM \"/xml/dtds/cross-domain-policy.dtd\">\n"
		"<cross-domain-policy>\n"
		"\t<site-control permitted-cross-domain-policies=\"master-only\"/>\n"
		"\t<allow-access-from domain=\"*\" to-ports=\"843,"sv << port << ",583\" secure=\"false\" />\n"
		"</cross-domain-policy>"sv;
	forWriting.close();
	flashPolicyPath = filename;

}

// This CloseHandler is spawned by OS in a separate thread to main(), so output will be unsynced,
// making it particularly messy in startup when you're waiting for user input and get a Ctrl-C instead.
// We don't write to std::cout here, unless we know server is running - which is when globalpump is set.

// Handles user interrupts and OS interrupts.
void CloseHandler(const int sig)
{
	// The majority of these signals, once returning, results in app termination.
	// For example, SIGSEGV is raised in this process when this process tries to read from invalid memory.
	// Attempting to continue app after that sort of handler will result in termination, and if it didn't,
	// the main thread probably has corrupt memory and can't continue anyway.
	// Others are notifications from the OS that the app is requested to exit.
	// 
	// Other handlers are special user signals that are safe to return from, such as pressing Ctrl-C.
	// 
	// It is also possible to manually send any interrupt number via an option to the kill command,
	// such as "kill /9 bluewing-cpp-server-linux.out", and raise it yourself e.g. "raise(SIGINT)".
	// For more info on signals:
	// https://unix.stackexchange.com/a/317496
	// Also note what functions you can call in a handler is heavily limited:
	// https://stackoverflow.com/a/2056565
	std::string signalType;

	// SIGINT: user pressed Ctrl-C. This is user quit request, and stops the server,
	// although it does not have to.
	if (sig == SIGINT)
		signalType = "SIGINT: interactive attention signal, probably a Ctrl+C"s;
	else if (sig == SIGQUIT)
	{
		statsDump = true;
		return;
	}
	// SIGHUP: user interactive terminal disconnected. This usually means
	// their SSH connection died.
	// 
	// Services/daemons do not run under interactive terminal, so they never get SIGHUP
	// naturally. As a result, sometimes services use the SIGHUP signal to reload config.
	// SIGUSR1 is otherwise used for this.
	// We don't have a config, so we ignore SIGHUP.
	// 
	// If you are running this server under a terminal and don't want the server dying
	// when terminal disconnects, then you run it under tmux, screen, nohup, etc.,
	// and detach with specific keypresses: tmux (ctrl-b, d), screen (ctrl-a, d).
	// Or you write it to be run as a service, e.g. under systemd.
	else if (sig == SIGHUP)
	{
		signalType = "SIGHUP: console user has gone away"s;
		return;
	}
	else if (sig == SIGCONT)
	{
		signalType = "SIGCONT: console user has returned"s;
		return;
	}
	else // We'll assume it's deadly as it's preferable to close nicely
		signalType = "Signal "s + std::to_string(sig);

	const bool appDiesAfterReturn = sig != SIGINT;
	// Only trigger once
	if (!shutdowned)
	{
		// Don't wait for user to press a key to end app (if we were going to)
		if (appDiesAfterReturn)
			requestUserInput = false;

		shutdowned = true;

		if (globalpump)
		{
			std::cout << red << u8"Got a "sv << signalType << u8", ending app."sv << lineEnd();
			globalpump->post_eventloop_exit();
		}
	}

	// Program may be terminated when handlers finish for most signals.
	// Stall until main thread finishes and exits itself.
	if (appDiesAfterReturn)
	{
		while (globalpump)
			std::this_thread::sleep_for(25ms);
	}
}

// Returns true if std::cin has a character to report. Uses OS-specific methods.
bool cinInputPending()
{
	// Terminal must not be line-buffered for this to work.
	fd_set set;
	struct timeval timeout;

	// Clear the set
	FD_ZERO(&set);
	FD_SET(STDIN_FILENO, &set);

	// Set timeout to zero for non-blocking behavior
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	// Check if input is available - as cin is line-buffered by default,
	// no input is reported until a newline (enter key) is pressed
	return select(STDIN_FILENO + 1, &set, NULL, NULL, &timeout) > 0;
}


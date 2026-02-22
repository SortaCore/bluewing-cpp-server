/* vim: set noet ts=4 sw=4 sts=4 ft=cpp:
 *
 * Created by Darkwire Software.
 *
 * This example server file is available unlicensed; the MIT license of liblacewing/Lacewing Relay does not apply to this file.
*/

// Includes Windows-specific headers
#include "WindowsConsole.hpp"

// Includes all global variables and headers that both Windows wchar_t and non-Windows char use.
#include "GenericConsole.hpp"

void GetUserKeyAndRestoreConsole()
{
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	std::wcin.clear();
	std::wcout.flush();
	SetConsoleCursorInfo(hStdout, &conOrigCursorInfo);
	FlushConsoleInputBuffer(hStdin);
	if (requestUserInput)
		_gettch();

	// Restore console modes
	SetConsoleMode(hStdout, conOrigOutputMode);
	SetConsoleMode(hStdin, conOrigInputMode);
	SetConsoleTextAttribute(hStdout, conOrigTextAttributes);
	SetConsoleCursorInfo(hStdout, &conOrigCursorInfo);
	SendMessage(consoleWin, WM_SETICON, ICON_SMALL, (LPARAM)conOrigSmallIcon);
	SendMessage(consoleWin, WM_SETICON, ICON_BIG, (LPARAM)conOrigBigIcon);
	DestroyIcon(conOrigSmallIcon);
	DestroyIcon(conOrigBigIcon);
}
lw_strview lineEnd(bool reprintStatsLine);

// Lacewing uses a sync inside lw_trace, which is singleton and never freed.
// lw_trace() is a no-op if _lacewing_debug isn't defined.
// To let garbage collector not see it as a leak:
#if defined(_CRTDBG_MAP_ALLOC) && defined(_lacewing_debug)
extern "C" { extern _lw_sync* lw_trace_sync; }
#endif

std::wstringstream lastTimeAndStatsSS;
std::wstring lastTimeAndStats;

// Reprints the time and statistics line. Called by lineEnd() and when stats timer ticks.
void ReprintStatisticsLine()
{
	// We don't maintain stats line if we're not console.
	// We also should not print if the server is pre-startup or currently shutting down.
	if (!isConsoleOutput || lastTimeAndStats.empty())
		return;

	assert(!lastTimeAndStats.empty());
	std::wcout << white << lastTimeAndStats;
	std::wcout.flush();
}

// Pads the last output line and inserts newline, appending either time to next line, or reprinting statistics
// @param reprintStatsLine if true, prints the statistics line again; if false, prints time only,
//						   expecting another line written immediately by caller
std::wstring_view lineEnd(bool reprintStatsLine = true)
{
	// If we're not outputting to console, we don't want to pad
	if (!isConsoleOutput)
	{
		lw_cout << L"\r\n"sv;
		if (!reprintStatsLine)
			std::wcout << timeBuffer;
		return L""sv;
	}
		
	// Last line wrote to here
	int consolex = 0, consoleWidth = 0, charsToFill = 15;
	CONSOLE_SCREEN_BUFFER_INFO csbi = {};
	if (GetConsoleScreenBufferInfo(hStdout, &csbi))
	{
		consolex = csbi.dwCursorPosition.X;
		// A blank line? >:(
		// could also occur if writing multiple lines
		assert(consolex);
		consoleWidth = csbi.dwSize.X;
		charsToFill = consoleWidth - consolex;
		assert(charsToFill > 0);
	}
	// Fill blank space from end of orig line to end of console,
	// in case we wrote time line 50 chars, then wrote non-time <50 chars
	if (charsToFill)
		std::wcout << std::setw((std::streamsize)charsToFill) << L""sv << std::setw(0);

	std::wcout << L"\r\n"sv;
	if (reprintStatsLine)
		ReprintStatisticsLine();
	else // prepare for another line
		std::wcout << timeBuffer;
	return TEXT(""sv);
}

void CheckPort(const wchar_t * portStr, lw_ui16 * writeTo, std::function<void()> errInv)
{
	int portNum = _wtoi(portStr);

	// Port 843 reserved for Flash policy
	if (portNum == 843 || portNum <= 0 || portNum > std::numeric_limits<lw_ui16>::max())
	{
		std::wcout << red;
		errInv();
		std::wcout << L" had invalid value "sv << portStr << L'.' << lineEnd();
	}
	*writeTo = (lw_ui16)portNum;
	if ((writeTo != &mainPort && *writeTo == mainPort) ||
		(writeTo != &websocketNonSecurePort && *writeTo == websocketNonSecurePort) ||
		(writeTo != &websocketSecurePort && *writeTo == websocketSecurePort))
	{
		errInv();
		std::wcout << L" port "sv << portStr << L" was reused for several ports."sv << lineEnd();
	}
}
std::wstring GetConsoleLine(bool pass = false)
{
	assert(isConsoleOutput);

	// Due to running under debugger or other reasons, we aren't asking
	if (!requestUserInput)
	{
#ifdef _DEBUG
		std::wcout << L"(prompting disabled)\r\n"sv;
#endif
		return std::wstring();
	}

	std::wcout << userinput;

	std::wstring consoleInputLine;

	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo(hStdout, &csbi);
	if (pass)
	{
		// Strip foreground color from flags 0xF0, and set foreground from background color,
		// hiding the visuals - not the best solution but it's gonna be in memory anyway,
		// as server may be long-running and need to re-use the password
		int backColor = (csbi.wAttributes & ~0x000F) | ((csbi.wAttributes & 0x00F0) >> 8);
		SetConsoleTextAttribute(hStdout, backColor);
	}

	std::getline(std::wcin, consoleInputLine);

	if (consoleInputLine.empty())
		SetConsoleCursorPosition(hStdout, csbi.dwCursorPosition);
	if (pass)
	{
		SetConsoleTextAttribute(hStdout, csbi.wAttributes);
		SetConsoleCursorPosition(hStdout, csbi.dwCursorPosition);
		std::wcout << std::wstring(consoleInputLine.empty() ? 20 + (rand() % 50) : consoleInputLine.size(), L'*') << L"\r\n"sv;
	}
	else if (consoleInputLine.empty())
		std::wcout << L"(empty input)\r\n"sv;
	return consoleInputLine;
}
void GuessCertPath()
{
	if (wsFullChainPath.empty())
	{
		// Search local folder for matching files, then ask user
		if (lw_file_exists("./sslcert.pfx"))
		{
			wsPrivKeyPath = wsFullChainPath = "./sslcert.pfx"s;
			std::wcout << green << L"Auto-set cert file to sslcert.pfx from current directory."sv << lineEnd();
		}
		else if (lw_file_exists("./fullchain.pem") && lw_file_exists("./privkey.pem"))
		{
			wsPrivKeyPath = "./privkey.pem"s;
			wsFullChainPath = "./fullchain.pem"s;
			std::wcout << green << L"Auto-set cert files to privkey.pem and fullchain.pem from current directory."sv << lineEnd();
		}
		// Not found at all - if websocket insecure was on, they probably want secure
		else if (websocketNonSecurePort)
			std::wcout << yellow << L"Couldn't find TLS certficate files - expecting either \"fullchain.pem\" and \"privkey.pem\", OR \"sslcert.pfx\" in app folder."sv << lineEnd();
	}
}
bool GetPortFromInput(const std::wstring_view req, lw_ui16 * writeTo, bool requireCert, lw_ui16 defaultVal)
{
	// Assume defaults will be fine if not prompting for settings
	if (!requestUserInput && !requireCert)
	{
		*writeTo = defaultVal;
		return true;
	}

	std::wstring consoleInputLine;
	if (requestUserInput && !requireCert)
		std::wcout << blue << L"Enter a "sv << req << L" port (leave empty for default " << defaultVal << L"):\r\n"sv;
	// Cert is required for this port, and we don't have cmdline arg
	else
	{
		GuessCertPath();

		if (!requestUserInput)
		{
			*writeTo = defaultVal;
			return true;
		}
		std::wcout << blue << L"Enter a "sv << req << L" port (leave empty for default "sv << defaultVal <<
			L", or pass 0 to disable secure websocket):\r\n"sv;
	}
	consoleInputLine = GetConsoleLine();

	bool good = true;
	if (consoleInputLine.empty())
	{
		// User pressed Ctrl-C during input
		if (shutdowned)
			return (good = false);
		*writeTo = defaultVal;
	}
	else
	{
		CheckPort(consoleInputLine.c_str(), writeTo, [&]() {
			std::wcout << L"Invalid input: "sv;
			good = false;
		});
	}
	// Cert is required for this port, and we don't have cmdline arg
	if (good && requireCert && *writeTo != 0)
	{
		if (wsFullChainPath.empty())
		{
			std::wcout << blue << L"Enter a path to TLS certificate file (combined PFX or full chain PEM), or leave empty to disable websocket secure hosting:\r\n"sv;
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
			std::wcout << blue << L"Enter a path to SSL priv key certificate file (PFX or PEM), or leave empty if part of chain file:\r\n"sv;
			consoleInputLine = GetConsoleLine();
			wsPrivKeyPath = consoleInputLine.empty() ? wsFullChainPath : WideToUTF8(consoleInputLine);
		}

		if (wsPassPhrase.empty())
		{
			std::wcout << blue << L"Enter a password to the certificate file(s), or leave empty if none:\r\n"sv;
			consoleInputLine = GetConsoleLine(true);
			wsPassPhrase = WideToUTF8(consoleInputLine);
		}
	}

	return good;
}

// Inserts commas as thousand separators
std::wstring bignum(const std::uint64_t n)
{
	std::wstring output = std::to_wstring(n);
	for (std::size_t i = 1, e = (std::size_t)std::ceil((float)output.size() / 3.f); i < e; ++i)
		output.insert(output.cend() - (i * 4) + 1, L',');
	return output;
}

int wmain(int argc, wchar_t* argv[])
{
	// Enable memory tracking (does nothing in Release)
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

#ifdef _DEBUG
	if (IsDebuggerPresent())
		system("cls");
#endif

	// Handle closing nicely
	SetConsoleCtrlHandler(CloseHandler, TRUE);

	// We don't use C-style printf(), so desync.
	// It's unclear whether cout or printf is faster; and some say cout is faster only with a fast locale.
	bool sync = std::ios_base::sync_with_stdio(false);

	// For Unicode text format
	init_locale();

	// For console text colouring
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	// If running under debugger, we may not care to ask for settings
	if (IsDebuggerPresent())
		requestUserInput = requestUserInputUnderDebugger;

	OnTimerTick(nullptr);

	// Get current app folder
	{
		std::wstring filenameBuf;
		filenameBuf.resize(256);
		do
		{
			std::size_t bytes = GetModuleFileNameW(NULL, filenameBuf.data(), (DWORD)filenameBuf.size());
			if (bytes == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				std::wcout << red << L"Flash policy couldn't be created. Looking up current app folder failed."sv << lineEnd();
				goto cleanup;
			}
			if (bytes < filenameBuf.size())
			{
				if (filenameBuf[bytes - 1] == '\0')
					--bytes;
				filenameBuf.resize(bytes);
				break;
			}
			filenameBuf.resize(filenameBuf.size() << 1);
		} while (true);

		static_assert(std::string::npos + 1 == 0);
		const std::size_t lastSlash = filenameBuf.find_last_of(L"\\/"sv);
		if (lastSlash == std::string::npos)
		{
			std::wcout << red << L"Flash policy couldn't be created. Current app folder made no sense."sv << lineEnd();
			goto cleanup;
		}
		appFolder = filenameBuf.substr(0, lastSlash);
	}

	// Parse passed args
	int numProgCmdArgs = 0;
	bool requireAdmin = false;
	{
		wchar_t** argsC = argv;
		numProgCmdArgs = argc;
		bool bad = false;
		if (numProgCmdArgs > 1)
		{
			auto setport = [&](std::size_t argCIdxName, lw_ui16* writeTo) {
				if (argCIdxName + 1 >= numProgCmdArgs)
				{
					std::wcout << L"Invalid cmdline: " << argsC[argCIdxName] << L" had no following value.\r\n"sv;
					return (bad = true);
				}

				CheckPort(argsC[argCIdxName + 1], writeTo, [&]() {
					std::wcout << L"Invalid cmdline: "sv << argsC[argCIdxName];
					bad = true;
				});
				return !bad;
			};
			auto setpath = [&](std::size_t argCIdxName, std::string* writeTo) {
				if (argCIdxName + 1 >= numProgCmdArgs)
				{
					std::wcout << L"Invalid cmdline: "sv << argsC[argCIdxName] << L" had no following value.\r\n"sv;
					return (bad = true);
				}

				// If flash policy path is specified, it must exist
				HANDLE h = CreateFileW(argsC[argCIdxName + 1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (h == INVALID_HANDLE_VALUE)
				{
					std::wcout << L"Invalid cmdline: "sv << argsC[argCIdxName] << L" had invalid path \"" << argsC[argCIdxName + 1] << L".\r\n"sv;
					return (bad = true);
				}
				*writeTo = WideToUTF8(argsC[argCIdxName + 1]);
				// PFX may hold both priv key and full chain, but should only be passed once, as priv key
				if (writeTo == &wsFullChainPath && lw_u8str_icmp(*writeTo, wsPrivKeyPath))
				{
					std::wcout << L"Invalid cmdline: \""sv << argsC[argCIdxName] << L"\" cert path \""sv
						<< argsC[argCIdxName + 1] << L"\" was reused for both fullchain and priv key. "
						L"Only pass it for priv key if you're using a PFX with both.\r\n"sv;
					return (bad = true);
				}
				if (writeTo == &flashPolicyPath && (lw_u8str_icmp(*writeTo, wsFullChainPath) || lw_u8str_icmp(*writeTo, wsPrivKeyPath)))
				{
					std::wcout << L"Invalid cmdline: \""sv << argsC[argCIdxName] << L"\" policy path \""sv
						<< argsC[argCIdxName + 1] << L"\" was reused for a websocket cert path.\r\n"sv;
					return (bad = true);
				}

				return true;
			};

			for (std::size_t i = 1; i < numProgCmdArgs;)
			{
				if (argsC[i][0] == L'/' || argsC[i][0] == L'-')
					++argsC[i];
				if (!_wcsicmp(argsC[i], L"mainPort") && setport(i, &mainPort) ||
					!_wcsicmp(argsC[i], L"wsPort") && setport(i, &websocketNonSecurePort) ||
					!_wcsicmp(argsC[i], L"wssPort") && setport(i, &websocketSecurePort) ||
					!_wcsicmp(argsC[i], L"certFullChainPath") && setpath(i, &wsFullChainPath) ||
					!_wcsicmp(argsC[i], L"certPrivKeyPath") && setpath(i, &wsPrivKeyPath))
				{
					i += 2;
					continue;
				}
				if (!_wcsicmp(argsC[i], L"flashPolicyPath") && setpath(i, &flashPolicyPath))
				{
					flashEnabled = true;
					i += 2;
					continue;
				}
				if (!_wcsicmp(argsC[i], L"enableFlash"))
				{
					if (!flashPolicyPath.empty())
						std::wcout << L"Warning: cmdline "sv << argsC[i] << L" does not need passing if you set the policy path.\r\n"sv;
					flashEnabled = true;
					++i;
					continue;
				}
				if (!_wcsicmp(argsC[i], L"requireAdmin"))
				{
					requireAdmin = true;
					++i;
					continue;
				}
				if (!_wcsicmp(argsC[i], L"certPassPhrase"))
				{
					if (i + 1 >= numProgCmdArgs)
					{
						std::wcout << L"Invalid cmdline: "sv << argsC[i] << L" had no following value.\r\n"sv;
						bad = true;
						break;
					}
					wsPassPhrase = WideToUTF8(argsC[i + 1]);
					i += 2;
					continue;
				}
				if (!_wcsicmp(argsC[i], L"welcomeMsg"))
				{
					if (i + 1 >= numProgCmdArgs)
					{
						std::wcout << L"Invalid cmdline: "sv << argsC[i] << L" had no following value.\r\n"sv;
						bad = true;
						break;
					}
					welcomeMessage = WideToUTF8(argsC[i + 1]);
					i += 2;
					continue;
				}
				if (!_wcsicmp(argsC[i], L"tcpClientUploadCap") || !_wcsicmp(argsC[i], L"totalUploadCap"))
				{
					if (i + 1 >= numProgCmdArgs)
					{
						std::wcout << L"Invalid cmdline: "sv << argsC[i] << L" had no following value.\r\n"sv;
						bad = true;
						break;
					}
					int capBytes = _wtoi(argsC[i + 1]);
					if (capBytes < 0)
					{
						std::wcout << L"Invalid cmdline: "sv << argsC[i] << L" had invalid value "sv << capBytes << L" bytes.\r\n"sv;
						bad = true;
						break;
					}
					if (!_wcsicmp(argsC[i], L"tcpClientUploadCap"))
						tcpClientUploadCap = (std::size_t)capBytes;
					else
						totalUploadCap = (std::size_t)capBytes;
					i += 2;
					continue;
				}
				// Give help
				if (!_wcsicmp(argsC[i], L"?") || !_wcsicmp(argsC[i], L"help"))
				{
					std::wcout << L"==== " PROJECT_NAME " "sv;
#					ifdef _DEBUG
					std::wcout << L"debug"sv;
#					else
					std::wcout << L"release"sv;
#					endif
					std::wcout << L" build "sv << lacewing::relayserver::buildnum << L" cmdline options ====\r\n"
						"bluewing-cpp-server /welcomeMsg \"message\" /mainPort 6121\r\n"
						"  /enableFlash /flashPolicyPath \"path to xml\"\r\n"
						"  /wsPort 80 /wssPort 443 /certFullChainPath \"...full-chain.pem\" /certPrivKeyPath \"...privkey.pem\" /certPassPhrase \"password\"\r\n"
						"  /requireAdmin /tcpClientUploadCap bytespersec /totalUploadCap bytespersec\r\n"
						"\r\n"
						"Defaults if command-lines and passed, and nothing is specified:\r\n"
						"  Main port 6121. Flash and WebSocket not hosting.\r\n"
						"  To reply to invalid UDP with ICMP Unreachable, the server app must be running with admin permissions.\r\n"
						"  Cert chain will be loaded from fullchain.pem + privkey.pem files, or from sslcert.pfx, in current directory.\r\n"
						"    No password is expected, if none is provided by cmdline.\r\n"
						"  Flash will be disabled by default. If enabled, it will always host policy on port 843.\r\n"
						"    Specifying /enableFlash without /flashPolicyPath will generate a flash policy in current directory.\r\n"
						"  TCP caps will be unlimited for both single-client (tcpClientUploadCap) and all-client (totalUploadCap).\r\n"
						"  UDP cap is 4/5th of TCP cap, so that UDP will not be the cause of exceeding the client cap.\r\n"
						"  Welcome message will contain build number, and if upload caps are active, will warn about automatic bans.\r\n"
						"====\r\n"sv;
					bad = true;
					break;
				}

				if (bad)
					break;

				std::wcout << L"Invalid cmdline: "sv << argsC[i] << L" was not recognised.\r\n"sv;
				bad = true;
				break;
			}
		}

		if (bad)
			return EINVAL;
	}

	// Backup current console config for restoring
	// GetConsoleMode fails if not console (e.g. redirected stdout to file)
	isConsoleOutput = GetConsoleMode(hStdout, &conOrigOutputMode);

	if (isConsoleOutput)
	{
		GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &conOrigInputMode);
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(hStdout, &csbi);
		conOrigTextAttributes = csbi.wAttributes;
		GetConsoleCursorInfo(hStdout, &conOrigCursorInfo);

		// Lock to UTF-16 output only. This is safe as we only read valid UTF-8 text from server messages;
		// Bluewing does not allow invalid UTF-8 in text messages
		fflush(stdout);
		_setmode(_fileno(stdout), _O_U16TEXT);
		fflush(stderr);
		_setmode(_fileno(stderr), _O_U16TEXT);

		// Used when overwriting the status line that sits at end of console
		std::wcout.fill(L' ');

		// Same as outputting white but without time buffer
		SetConsoleTextAttribute(hStdout, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

		// Set console icon
		{
			// GetConsoleWindow() and undoc'd Kernel32 func SetConsoleIcon() doesn't work in Win 11,
			// presumably due to psuedoconsole.
			// GetForegroundWindow() will grab any app's foreground window, not just this one.
			consoleWin =  GetActiveWindow();
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

		// Check for admin membership, required for ICMP raw sockets, which are used for UDP error replies
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
					std::wcout << red << L"Server is set by command-line to require admin, and is not running as admin. Server start aborted.\r\n"sv;
					goto cleanup;
				}
				std::wcout << red << L"Warning: server is not running with admin privileges. Resetting UDP connections with ICMP will not be possible.\r\n"sv;
			}
		}

		// If console output, and no cmd args were passed at all, ask user for input
		if (numProgCmdArgs <= 1)
		{
			if (!GetPortFromInput(L"main"sv, &mainPort, false, 6121) ||
				!GetPortFromInput(L"WebSocket insecure"sv, &websocketNonSecurePort, false, 80) ||
				!GetPortFromInput(L"WebSocket secure"sv, &websocketSecurePort, true, 443))
			{
				goto cleanup;
			}
			if (welcomeMessage.empty() && requestUserInput)
			{
				std::wcout << blue << L"Enter a welcome message, or leave blank for the default message with server build:\r\n"sv;
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
					std::wcout << red << L"Server was passed secure port but no certificate paths.\r\n"sv;
					goto cleanup;
				}
			}
		}
	}

	// Block some IPs by default
	//misbehavingIPList.emplace_back(MisbehavingIPEntry("127.0.0.1"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, std::string_view(), laceclock::now() + 24h));
	misbehavingIPList.emplace_back(MisbehavingIPEntry("176.59.131.111"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, std::string_view(), laceclock::now() + 24h));

	// No further code in this server uses input text, except end of app, so untie the cin/cout syncing
	std::wcin.tie(nullptr);
	std::cin.tie(nullptr);

	globalpump = lacewing::eventpump_new();
	globalserver = new lacewing::relayserver(globalpump);
	globalmsgrecvcounttimer = lacewing::timer_new(globalpump, "global message receiving tick-over");
	lacewing::error error = nullptr;

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
	#else
		if (tcpClientUploadCap)
		{
			welcMsg << "This is a Bluewing Server build "sv << lacewing::relayserver::buildnum <<
				". An upload cap is in place. Please pay attention to Sent server -> peer text messages on subchannels 0 and 1,"
				" or you may be banned."sv;
		}
		else
			welcMsg << "This is a Bluewing Server build "sv << lacewing::relayserver::buildnum << '.';
	#endif
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

	ReprintStatisticsLine();

	globalserver->host(mainPort);

	if (!flashPolicyPath.empty())
		globalserver->flash->host(flashPolicyPath.c_str());

	if (websocketNonSecurePort || websocketSecurePort)
		globalserver->host_websocket(websocketNonSecurePort, websocketSecurePort);

	// Update messages received/sent line every 1 sec
	globalmsgrecvcounttimer->start(1000L);

	// Hide console cursor by default - the statistics line CR makes it flash at start of line (ugly)
	{
		CONSOLE_CURSOR_INFO info{ 100, FALSE };
		SetConsoleCursorInfo(hStdout, &info);
	}

	// Start main event loop
#ifdef _DEBUG
	error = globalpump->start_eventloop();
#else
	try {
		error = globalpump->start_eventloop();
	}
	catch (...)
	{
		error = lacewing::error_new();
		error->add("Crash happened.");
	}
#endif

	if (error)
		std::wcout << red << L"Error occurred in pump: "sv << error->tostring() << lineEnd();

cleanup:
	shutdowned = true;
	// Cleanup time
	clientdata.clear();
	lacewing::timer_delete(globalmsgrecvcounttimer);
	bool goodInit = globalserver != nullptr;
	if (goodInit)
	{
		globalserver->unhost();
		globalserver->flash->unhost();
		globalserver->unhost_websocket(true, true);
		delete globalserver;
	}
	lacewing::eventpump_delete(globalpump);

	if (!flashPolicyPath.empty() && deleteFlashPolicyAtEndOfApp)
		DeleteFileW(UTF8ToWide(flashPolicyPath).c_str());

	// Lacewing uses a sync inside lw_trace, which is singleton and never freed.
	// lw_trace() is a no-op if _lacewing_debug isn't defined.
	// To let garbage collector not see it as a leak:
#if defined(_CRTDBG_MAP_ALLOC) && defined(_lacewing_debug)
	lw_sync_delete(lw_trace_sync);
#endif

	if (goodInit)
	{
		std::wcout << green << L"Program completed."sv << lineEnd(false);
		std::wcout << L"Total bytes: "sv << bignum(serverdata.in.total.bytes) << L" in, "sv << bignum(serverdata.out.total.bytes) << L" out."sv << lineEnd(false);
		std::wcout << L"Total msgs: "sv << bignum(serverdata.in.total.msg) << L" in, "sv << bignum(serverdata.out.total.msg) << L" out."sv << lineEnd(false);
		std::wcout << L"Max msgs in 1 sec: "sv << bignum(serverdata.in.highestSec.msg) << L" in, "sv << bignum(serverdata.out.highestSec.msg) << L" out (may be diff seconds)."sv << lineEnd(false);
		std::wcout << L"Max bytes in 1 sec: "sv << bignum(serverdata.in.highestSec.bytes) << L" in, "sv << bignum(serverdata.out.highestSec.bytes) << L" out.\r\n"sv;
	}

	if (isConsoleOutput && requestUserInput)
		std::wcout << white << L"\rPress any key to exit.\r\n"sv;

	// re-sync console input + output
	std::wcin.tie(&std::wcout);
	std::cin.tie(&std::cout);

	// Restore console modes
	if (isConsoleOutput)
		GetUserKeyAndRestoreConsole();

	return 0;
}

void UpdateTitle(std::size_t clientCount)
{
	std::size_t channelCount = globalserver->channelcount();
	wchar_t name[128];
	swprintf_s(name, std::size(name), L"Bluewing C++ Server - %zu client%s connected in %zu channel%s",
		clientCount, clientCount == 1 ? L"" : L"s",
		channelCount, channelCount == 1 ? L"" : L"s");
	SetConsoleTitleW(name);

	if (serverdata.maxClients < clientCount)
		serverdata.maxClients = clientCount;
	if (serverdata.maxChannels < channelCount)
		serverdata.maxChannels = channelCount;
}

// Trusted IPs can ask for statistics and unban any IP, and cannot be banned themselves
static bool IsIPTrusted(const std::string_view addr)
{
	// Allow only from LAN addresses, and Darkwire
	// This does not check IPv6 addresses, you may want to do that
	return addr._Starts_with("10."sv) || // class A private
		// Class B private is subsection of 172.16.x.x and not checked for here
		addr._Starts_with("192.168.1."sv) || // class C private
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
	const std::wstring addrW = UTF8ToWide(client->getaddress());

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

	std::wcout << green << TXT("New client ID ") << client->id() << L", IP "sv << addrW << L" connected."sv << lineEnd();
	clientdata.push_back(std::make_unique<clientstats>(client));
}
/**
 * @brief Handles client disconnect events.
 * @param server The server, always globalserver.
 * @param client The client, never null.
 * @remarks
 * client.istrusted() indicates whether the client sent invalid Bluewing messages, and is getting kicked
 * for violations, or whether the client is disconnecting of its own accord.
 * You may have disconnects reported via OnError, if the connection was not Relay.
*/
void OnDisconnect(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> client)
{
	UpdateTitle(server.clientcount());
	std::string name = client->name();
	name = !name.empty() ? name : "[unset]"sv;
	const std::string_view addr = client->getaddress();
	const auto a = ClientDataByClientPtr(client);

	std::wcout << green << L"Client ID "sv << client->id() << L", name "sv << UTF8ToWide(name) << L", IP "sv << UTF8ToWide(addr) << L" disconnected."sv;
	if (a != clientdata.cend())
		std::wcout << L" Uploaded "sv << bignum((**a).total.bytes) << L" bytes in "sv << bignum((**a).total.msg) << L" msgs total."sv;
	std::wcout << lineEnd();

	if (!client->istrusted() && !IsIPTrusted(addr))
	{
		const auto entry = std::find_if(misbehavingIPList.begin(), misbehavingIPList.end(), [&](const MisbehavingIPEntry & b) { return b.ip == addr; });
		if (entry == misbehavingIPList.end())
		{
			std::wcout << yellow << L"Due to malformed protocol usage, created a IP ban entry."sv << lineEnd();
			AddMisbehavingIPEntry(**a, addr, "Broken Lacewing protocol", laceclock::now() + 30min);
		}
		else
		{
			std::wcout << yellow << L"Due to malformed protocol usage, increased their ban likelihood."sv << lineEnd();
			++entry->disconnects;
		}
	}
	if (a != clientdata.cend())
		clientdata.erase(a);
}

/**
 * @brief Ticks over second-based statistics, bans users who have exceeded TCP upload cap.
 * @param timer The one-second timer, always globalmsgrecvcounttimer.
*/
void OnTimerTick(lacewing::timer timer)
{
	std::time_t rawtime = std::time(NULL);
	std::tm timeinfo = { 0 };
	std::time(&rawtime);
	if (!localtime_s(&timeinfo, &rawtime))
		std::wcsftime(timeBuffer, std::size(timeBuffer), L"%T | ", &timeinfo);
	else
		wcscpy_s(timeBuffer, std::size(timeBuffer), L"XX:XX:XX | ");

	// We're in startup, and only want to update the time
	if (!timer)
		return;

	serverdata.in.highestSec.SetToMaxOfCurrentAndThis(serverdata.in.cur);
	serverdata.out.highestSec.SetToMaxOfCurrentAndThis(serverdata.out.cur);
	serverdata.in.total += serverdata.in.cur;
	serverdata.out.total += serverdata.out.cur;
	serverdata.in.lastSec = serverdata.in.cur;
	serverdata.out.lastSec = serverdata.out.cur;
	serverdata.in.cur = serverdata.out.cur = { 0, 0 };

	if (isConsoleOutput)
	{
		lastTimeAndStatsSS << L"Last sec received "sv << bignum(serverdata.in.lastSec.msg) << L" messages ("sv << bignum(serverdata.in.lastSec.bytes)
			<< L" bytes), forwarded "sv << bignum(serverdata.out.lastSec.msg) << L" ("sv << bignum(serverdata.out.lastSec.bytes) << L" bytes).\r"sv;
		lastTimeAndStats = lastTimeAndStatsSS.str();
		lastTimeAndStatsSS.clear();
		lastTimeAndStatsSS.str(std::wstring());
		ReprintStatisticsLine();
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

	if (!tcpClientUploadCap)
		return;

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
			[&](const MisbehavingIPEntry &b) { return b.ip == addr; });
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
 * Text inside binary is not checked as binary messages are opaque.
*/
void OnServerMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	serverdata.in.cur.AddMsg(data.size());

	// If you want to log all incoming messages to console e.g. for debug, here is a way
	if constexpr (false)
	{
		std::string name = senderclient->name();
		name = !name.empty() ? name : "[unset]"sv;

		std::wcout << white << L"Message from client ID "sv << senderclient->id() << L", name "sv << UTF8ToWide(name)
			<< L':' << lineEnd(false) << UTF8ToWide(data) << lineEnd(false)
			<< L"blasted = "sv << (blasted ? L"yes"sv : L"no"sv)
			<< L", subchannel = "sv << subchannel << L", variant = "sv << variant
			<< L'.' << lineEnd();
	}

	// The default messages handled in bluewing-cpp-server, which are not required by Bluewing,
	// are only text messages that are TCP on subchannel 0.
	if (blasted || variant != 0 || subchannel != 0)
	{
		const std::string_view addr = senderclient->getaddress();
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
	//   "give my ip"
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

	// The remote IP request is "give my ip", and any user can request it.
	if (data == "give my ip"sv)
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

			if (data == "send report"sv)
			{
				str << "Reporting server status. Channel count: "sv << globalserver->channelcount() << ", client count: "sv << globalserver->clientcount() << "\n\n"sv;
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
						str << "\n";
					}
					str << "\n";
				}

				{
					str << "=== Client list:\n"sv;
					{
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

							str << "\n";
						}
					}
					str << "\n";
				}

				str << "\n=== Total server stats so far:\n"sv;
				str << "Last second: "sv << serverdata.in.lastSec.bytes << " bytes in, in "sv << serverdata.in.lastSec.msg << " msgs, "sv
					<< serverdata.out.lastSec.bytes << " bytes out, in "sv << serverdata.out.lastSec.msg << " msgs.\n"sv;
				str << "Biggest second: "sv << serverdata.in.highestSec.bytes << " bytes in. "sv << serverdata.in.highestSec.msg << " msgs in. "sv
					<< serverdata.out.highestSec.bytes << " bytes out. "sv << serverdata.out.highestSec.msg << " msgs out.\n";
				str << "Total run: "sv << serverdata.in.total.bytes << " bytes in, in "sv << serverdata.in.total.msg << " msgs, "sv
					<< serverdata.out.total.bytes << " bytes out, in "sv << serverdata.out.total.msg << " msgs.\n"sv;
				str << "Max num clients in this run: "sv << serverdata.maxClients << ". Max channels: "sv << serverdata.maxChannels << ".\n"sv;

				str << "\n=== Ban list has "sv << misbehavingIPList.size() << " entries:\n"sv;
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
						// Format: Mo, 15.06.2009 20:20:00
						char time[64];
						std::strftime(time, sizeof(time), "%d/%m/%Y %H:%M:%S", ptm);
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
			senderclient->send(0, msg);
			return;
		}
	}

	// Otherwise, the message is assumed to be something the user intended to display on the console.
	// First

	std::string name = senderclient->name();
	name = !name.empty() ? name : "[unset]"sv;

	// Sanitize possible console commands by only allowing alphanum, space, and punct
	std::wstring msg = UTF8ToWide(data);
	auto msgIt = std::find_if(msg.cbegin(), msg.cend(), [](const wchar_t w) {
		return w == (wchar_t)0x1B || (!iswalnum(w) && !iswpunct(w) && w != L' ');
	});
	if (msgIt == msg.cend())
		std::wcout << white;
	else
		std::wcout << red;

	std::wcout << L"Message from client ID "sv << senderclient->id()
		<< L", name "sv << UTF8ToWide(name) << L':' << lineEnd(false);
	if (msgIt == msg.cend())
		std::wcout << msg;
	else
	{
		std::wcout << L"[Message was suppressed due to forbidden char \""sv << *msgIt
			<< L"\" at index "sv << std::distance(msg.cbegin(), msgIt) << L'.';
	}

	std::wcout << lineEnd();
}
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
	serverdata.in.cur.AddMsg(data.size());

	// UDP upload limit is 4/5 of TCP limit; if a TCP limit is set, a UDP one is too
	if (tcpClientUploadCap && blasted && serverdata.out.cur.bytes > totalUploadCap * 4 / 5)
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

	serverdata.out.cur.AddMsg(data.size());
	server.clientmessage_permit(senderclient, viachannel, receiverclient, blasted, subchannel, data, variant, true);
}

void OnChannelMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	std::shared_ptr<lacewing::relayserver::channel> channel,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	serverdata.in.cur.AddMsg(data.size());

	// UDP upload limit is 4/5 of TCP limit; if a TCP limit is set, a UDP one is too
	if (tcpClientUploadCap && blasted && serverdata.out.cur.bytes > totalUploadCap * 4 / 5)
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
	serverdata.out.cur.AddMulti(channel->clientcount() - 1U, data.size());
}

// Until we have a better general error handler for Lacewing...
extern "C" void always_log(const char* c, ...)
{
	char output[1024];
	va_list v;
	va_start(v, c);
	int numChars = vsprintf_s(output, std::size(output), c, v);
	if (numChars <= 0)
		std::abort();
	wchar_t * output_wide = lw_char_to_wchar(output, numChars);
	std::wstring_view outputWideSV(output_wide);
	if (outputWideSV.back() == L'\n')
		outputWideSV.remove_suffix(1);
	if (outputWideSV.back() == L'\r')
		outputWideSV.remove_suffix(1);

	// We need to split into lines and do preline() for each
	assert(outputWideSV.find(L'\n') == std::wstring_view::npos);

	std::wcout << yellow << L"(AL) "sv << outputWideSV << lineEnd();
	free(output_wide);
	va_end(v);
}

void GenerateFlashPolicy(int port)
{
	std::wstring filename = appFolder + L"FlashPlayerPolicy.xml"s;

	// File already exists; just use it
	DWORD policyAttr = GetFileAttributesW(filename.c_str());
	if (policyAttr != INVALID_FILE_ATTRIBUTES && !(policyAttr & FILE_ATTRIBUTE_DIRECTORY))
	{
		flashPolicyPath = WideToUTF8(filename);
		return;
	}

	HANDLE forWriting = CreateFileW(filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (forWriting == NULL || forWriting == INVALID_HANDLE_VALUE)
	{
		std::wcout << red << L"Flash policy couldn't be created. Opening file \""sv << filename
			<< L"\" for writing in current app folder failed."sv << lineEnd();
		return;
	}

	deleteFlashPolicyAtEndOfApp = true;

	std::stringstream flashPolicy;
	flashPolicy << "<?xml version=\"1.0\"?>\r\n"sv
		"<!DOCTYPE cross-domain-policy SYSTEM \"/xml/dtds/cross-domain-policy.dtd\">\r\n"sv
		"<cross-domain-policy>\r\n"sv
		"\t<site-control permitted-cross-domain-policies=\"master-only\"/>\r\n"sv
		"\t<allow-access-from domain=\"*\" to-ports=\"843," << port << ",583\" secure=\"false\" />\r\n"sv
		"</cross-domain-policy>"sv;
	const std::string policyStr = flashPolicy.str();
	if (!WriteFile(forWriting, policyStr.c_str(), (DWORD)policyStr.size(), NULL, NULL))
	{
		std::wcout << red << L"Flash policy couldn't be created. Writing to file "sv << filename << L" failed."sv << lineEnd();
		CloseHandle(forWriting);
		DeleteFileW(filename.c_str());
		return;
	}

	CloseHandle(forWriting);
	flashPolicyPath = WideToUTF8(filename);
}

BOOL WINAPI CloseHandler(DWORD ctrlType)
{
	if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT)
	{
		if (!shutdowned)
		{
			shutdowned = true;

			// This CloseHandler is spawned by OS in a separate thread, so it will mess up console display
			// particularly in startup when you're waiting for user input and get a Ctrl-C instead.
			// Preferable that you don't write to std::wcout here, unless you know server is running.
			if (globalpump)
			{
				std::wcout << red << L"Got Ctrl-C or Close, ending app."sv << lineEnd();
				globalpump->post_eventloop_exit();
			}
		}

		// This kills app on handler return, so delay
		if (ctrlType == CTRL_CLOSE_EVENT)
			while (globalpump)
				Sleep(5);
		
		return true;
	}
	else if (ctrlType == CTRL_BREAK_EVENT)
	{
		std::wcout << red << L"Ignoring Ctrl-Break."sv << lineEnd();
		return true;
	}
	return false;
}

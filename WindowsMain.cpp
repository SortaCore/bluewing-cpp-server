/* vim: set noet ts=4 sw=4 sts=4 ft=cpp:
 *
 * Created by Darkwire Software.
 *
 * This example server file is available unlicensed; the MIT license of liblacewing/Lacewing Relay does not apply to this file.
*/

// If the user hasn't specified a target Windows version via _WIN32_WINNT, and is using an _xp toolset (indicated by _USING_V110_SDK71_),
// then _WIN32_WINNT will be set to Windows XP (0x0501).
#if !defined(_WIN32_WINNT) && defined(_USING_V110_SDK71_)
	#define _WIN32_WINNT _WIN32_WINNT_WINXP
	#define WINVER _WIN32_WINNT_WINXP
#endif

// For memory leak finding
#ifdef _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <iostream>
#include <ctime>
#include <sstream>
#include <algorithm>
#include <vector>
#include "ConsoleColors.hpp"
#include "Lacewing\Lacewing.h"

using namespace std::string_view_literals;

#include <locale>
#include <locale.h>
#include <conio.h>

#ifndef MS_STDLIB_BUGS
#  if ( _MSC_VER || __MINGW32__ || __MSVCRT__ )
#    define MS_STDLIB_BUGS 1
#  else
#    define MS_STDLIB_BUGS 0
#  endif
#endif

#if MS_STDLIB_BUGS
#  include <io.h>
#  include <fcntl.h>
#endif

void init_locale(void)
{
	// Constant for fwide().
	static const int wide_oriented = 1;

#if MS_STDLIB_BUGS
	// Windows needs a little non-standard magic.
	static const char locale_name[] = ".1200";
	_setmode(_fileno(stdout), _O_WTEXT);
#else
	// The correct locale name may vary by OS, e.g., "en_US.utf8".
	static const char locale_name[] = "";
#endif

	setlocale(LC_ALL, locale_name);
	fwide(stdout, wide_oriented);
}

// Define if you want Flash hosted. Policy file will automatically be generated.
#define FLASH_ENABLED

// Upload limit for ENTIRE SERVER, TCP + UDP, in bytes
// UDP messages received above 4/5ths of this limit will be discarded, so TCP has room
// TCP messages received above this limit are still delivered. See TCP_CLIENT_UPLOAD_CAP.
// #define TOTAL_UPLOAD_CAP 500000

// TCP upload limit for single clients, per second, in bytes.
// TCP messages received above this limit will send the client an error message
// and disconnect them.
// UDP upload limit is not defined.
// #define TCP_CLIENT_UPLOAD_CAP 3000

// Set this to 0 for the app to ask the user what port it is, on bootup;
// or to another number to use that by default
static const int FIXEDPORT = 6121;
// Set this to 0 for the app to disable websocket on either or both http/https variants.
// websocketSecure will not work without certificate loading before websocket host is called.
// WebSocket expects ./fullchain.pem and ./privkey.pem files, with no password, in same folder as executable.
// Windows can also use ./sslcert.pfx, make sure private key is inside, with no password.
static int websocketNonSecure = 80, websocketSecure = 443;



// Declarations - Lacewing handlers
void OnConnectRequest(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> client);
void OnDisconnect(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> client);
void OnTimerTick(lacewing::timer timer);
void OnError(lacewing::relayserver &server, lacewing::error error);
void OnServerMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant);
void OnChannelMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	std::shared_ptr<lacewing::relayserver::channel> channel,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant);
void OnPeerMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	std::shared_ptr<lacewing::relayserver::channel> viachannel, std::shared_ptr<lacewing::relayserver::client> receiverclient,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant);

// Declarations - functions
void GenerateFlashPolicy(int port);
void Shutdown();
void UpdateTitle(std::size_t clientCount);
BOOL WINAPI CloseHandler(DWORD ctrlType);

// Global variables
lacewing::eventpump globalpump;
lacewing::timer globalmsgrecvcounttimer;
lacewing::relayserver * globalserver;
std::string flashpolicypath;
bool deleteFlashPolicyAtEndOfApp;
static wchar_t timeBuffer[10];

// In case of idiocy
struct BanEntry
{
	std::string ip;
	int disconnects;
	std::string reason;
	std::string chListAtDisconnect;
	__time64_t resetAt;
	BanEntry(const std::string_view ip, const int disconnects, const std::string_view reason,
		const std::string_view chListAtDisconnect, const __time64_t resetAt) :
		ip(ip), disconnects(disconnects), reason(reason), chListAtDisconnect(chListAtDisconnect), resetAt(resetAt)
	{
		// yay
	}
};
static std::vector<BanEntry> banIPList;

struct lacestat {
	std::uint64_t msg = 0, bytes = 0;
	lacestat& operator += (const lacestat& s) {
		msg += s.msg;
		bytes += s.bytes;
		return *this;
	}
	void SetToMaxOfCurrentAndThis(const lacestat& s) {
		if (msg < s.msg)
			msg = s.msg;
		if (bytes < s.bytes)
			bytes = s.bytes;
	}
	void AddMsg(const std::size_t msgSize)
	{
		++msg;
		bytes += msgSize;
	}
	void AddMulti(const std::size_t msgCount, const std::size_t msgSize)
	{
		msg += msgCount;
		bytes += msgSize * msgCount;
	}
};

static struct {
	struct {
		lacestat cur, lastSec, total, highestSec;
	} in, out;
	std::size_t maxClients = 0, maxChannels = 0;
} serverdata;
struct clientstats
{
	std::shared_ptr<lacewing::relayserver::client> c;
	std::size_t wastedServerMessages = 0;
	lacestat cur, lastSec, total, highestSec;
	bool exceeded = false;
	clientstats(std::shared_ptr<lacewing::relayserver::client> _c) : c(_c) {}
};
static std::vector<std::shared_ptr<clientstats>> clientdata;

const char* sslPathCertChain = ".\\fullchain.pem";
const char* sslPathPrivKey = ".\\privkey.pem";
void AddBanEntry(const clientstats& c, const char* const addr, const std::string_view msg, const time_t tim)
{
	std::stringstream chList;
	auto writeLock = c.c->lock.createWriteLock();
	for (auto p : c.c->getchannels())
		chList << '[' << p->name() << "], "sv;

	std::string chListAtDisconnect = chList.str();
	if (!chListAtDisconnect.empty())
		chListAtDisconnect.resize(chListAtDisconnect.size() - 2);
	else
		chListAtDisconnect = "(empty)"sv;
	banIPList.push_back(BanEntry(addr, 1, msg, chListAtDisconnect, tim));
}

std::wstring UTF8ToWide(const std::string_view str)
{
	wchar_t * wide = lw_char_to_wchar(str.data(), (int)str.size());
	if (!wide)
		return std::wstring();
	const std::wstring wideStr = wide;
	free(wide);
	return wideStr;
}
std::wstring UTF8ToWide(const char * str)
{
	return UTF8ToWide(std::string_view(str));
}

static DWORD conOrigInputMode, conOrigOutputMode;
static WORD conOrigTextAttributes;

int ExitWithError(const char * msg, int error)
{
	std::wcout << red << UTF8ToWide(msg) << L", got error number "sv << error << L".\r\n"sv;
	std::wcout << L"Press any key to exit.\r\n"sv;

	// Clear input for getchar()
	std::wcin.clear();
	std::wcin.ignore();
	std::wcin.ignore();

	getwchar(); // wait for user keypress

	// Restore console modes
	SetConsoleMode(hStdout, conOrigOutputMode);
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), conOrigInputMode);
	SetConsoleTextAttribute(hStdout, conOrigTextAttributes);
	return 1;
}

// Lacewing uses a sync inside lw_trace, which is singleton and never freed.
// lw_trace() is a no-op if _lacewing_debug isn't defined.
// To let garbage collector not see it as a leak:
#if defined(_CRTDBG_MAP_ALLOC) && defined(_lacewing_debug)
extern "C" { extern _lw_sync* lw_trace_sync; }
#endif

int main()
{
	// Enable memory tracking (does nothing in Release)
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	// Handle closing nicely
	SetConsoleCtrlHandler(CloseHandler, TRUE);

	// We don't use C-style printf(), so desync.
	// It's unclear whether cout or printf is faster; and some say cout is faster only with a fast locale.
	std::ios_base::sync_with_stdio(false);

	// For Unicode text format
	init_locale();

	// For console text colouring
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	// Backup current console config for restoring
	{
		GetConsoleMode(hStdout, &conOrigOutputMode);
		GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &conOrigInputMode);
		CONSOLE_SCREEN_BUFFER_INFO csbi;
		GetConsoleScreenBufferInfo(hStdout, &csbi);
		conOrigTextAttributes = csbi.wAttributes;
	}

	//if (SetConsoleOutputCP(CP_UTF8) == FALSE)
	//	DebugBreak();

#ifdef _lacewing_debug
	FILE * f = NULL;
	if (fopen_s(&f, "Bluewing Server error.log", "w"))
		return ExitWithError("Couldn't open log file", errno);

	if (freopen_s(&f, "CONOUT$", "w", stderr))
	{
		fclose(f);
		return ExitWithError("Couldn't redirect error to log file", errno);
	}
#endif
	// Block some IPs by default
	//banIPList.push_back(BanEntry("127.0.0.1"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, std::string_view(), (_time64(NULL) + 24LL * 60LL * 60LL)));
	banIPList.push_back(BanEntry("176.59.131.111"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, std::string_view(), (_time64(NULL) + 24LL * 60LL * 60LL)));

	globalpump = lacewing::eventpump_new();
	globalserver = new lacewing::relayserver(globalpump);
	globalmsgrecvcounttimer = lacewing::timer_new(globalpump, "global message receiving tick-over");
	lacewing::error error = nullptr;

	{
		char message[256];
	#ifdef _DEBUG
		sprintf_s(message, "This is a Bluewing Server build %i. Currently under debug testing. "
			"You may be disconnected randomly as server is restarted.", lacewing::relayserver::buildnum);
	#elif TCP_CLIENT_UPLOAD_CAP
		sprintf_s(message, "This is a Bluewing Server build %i. An upload cap is in place. Please pay "
			"attention to Sent server -> peer text messages on subchannels 0 and 1, or you may be banned.",
			lacewing::relayserver::buildnum);
	#else
		sprintf_s(message, "This is a Bluewing Server build %i.", lacewing::relayserver::buildnum);
	#endif
		globalserver->setwelcomemessage(message);
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

	// Check port settings
	int port = FIXEDPORT;
	if constexpr (FIXEDPORT == 0)
	{
		std::wcout << L"Enter port number to begin (default 6121):"sv;

		{
			std::wstring portStr;
			std::getline(std::wcin, portStr);
			std::wstringstream lazy(portStr); lazy >> port;
			port = port <= 0 || port > 0xFFFF ? 6121 : port;
		}
	}
#ifdef FLASH_ENABLED
	GenerateFlashPolicy(port);
#endif

	// Update the current time in case host() errors, or try to connect before first tick
	OnTimerTick(globalmsgrecvcounttimer);

	// Host the thing
	std::wcout << green << L"Host started. Port "sv << port << L", build "sv << globalserver->buildnum << L". "sv <<
		(flashpolicypath.empty() ? L"Flash not hosting"sv : L"Flash policy hosting on TCP port 843"sv) << L'.' <<
		std::wstring(flashpolicypath.empty() ? 30 : 5, L' ') << L"\r\n"sv << white;

	// For loading from Windows certificate store (certmgr.msc), use websocket->load_sys_cert("Root", "yourdomain.com", "LocalMachine")

	if (websocketSecure)
	{
		if (!lw_file_exists(sslPathCertChain))
		{
			sslPathPrivKey = sslPathCertChain = ".\\sslcert.pfx";
			if (!lw_file_exists(sslPathCertChain))
			{
				std::wcout << yellow << L"Couldn't find TLS certficate files - expecting either \"fullchain.pem\" and \"privkey.pem\", OR \"sslcert.pfx\" in app folder.\r\n"
					L"Will continue webserver with just insecure websocket.\r\n"sv;
				websocketSecure = 0;
			}
			else if (!globalserver->websocket->load_cert_file(sslPathCertChain, sslPathPrivKey, ""))
			{
				std::wcout << red << L"Found but couldn't load TLS certificate file \"sslcert.pfx\". Aborting server.\r\n"sv;
				goto cleanup;
			}
		}
		else if (!globalserver->websocket->load_cert_file(sslPathCertChain, sslPathPrivKey, ""))
		{
			std::wcout << red << L"Found but couldn't load TLS certificate files \"fullchain.pem\" and \"privkey.pem\". Aborting server.\r\n"sv;
			goto cleanup;
		}
	}

	if (websocketNonSecure || websocketSecure)
	{
		std::wcout << green << L"WebSocket hosting. Port "sv;
		if (websocketNonSecure)
			std::wcout << websocketNonSecure << L" (non-secure, ws://xx)"sv;
		if (websocketNonSecure && websocketSecure)
			std::wcout << L" and port "sv;
		if (websocketSecure)
			std::wcout << websocketSecure << L" (secure, wss://xx)"sv;
		std::wcout << L".\r\n"sv << yellow;
	}
	std::wcout.flush();

	globalserver->host(port);

	if (!flashpolicypath.empty())
		globalserver->flash->host(flashpolicypath.c_str());

	if (websocketNonSecure || websocketSecure)
		globalserver->host_websocket(websocketNonSecure, websocketSecure);

	// Update messages received/sent line every 1 sec
	globalmsgrecvcounttimer->start(1000L);

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
		std::wcout << red << L"\r\n"sv << timeBuffer << L" | Error occurred in pump: "sv << error->tostring() << L"\r\n"sv;

	cleanup:
	// Cleanup time
	clientdata.clear();
	lacewing::timer_delete(globalmsgrecvcounttimer);
	globalserver->unhost();
	globalserver->flash->unhost();
	globalserver->unhost_websocket(true, true);
	delete globalserver;
	lacewing::pump_delete(globalpump);

	if (!flashpolicypath.empty() && deleteFlashPolicyAtEndOfApp)
		DeleteFileA(flashpolicypath.c_str());

	// Lacewing uses a sync inside lw_trace, which is singleton and never freed.
	// lw_trace() is a no-op if _lacewing_debug isn't defined.
	// To let garbage collector not see it as a leak:
#if defined(_CRTDBG_MAP_ALLOC) && defined(_lacewing_debug)
	lw_sync_delete(lw_trace_sync);
#endif

	std::wcout << green << timeBuffer << L" | Program completed.\r\n"sv;
	std::wcout << timeBuffer << L" | Total bytes: "sv << serverdata.in.total.bytes << L" in, "sv << serverdata.out.total.bytes << L" out.\r\n"sv;
	std::wcout << timeBuffer << L" | Total msgs: "sv << serverdata.in.total.msg << L" in, "sv << serverdata.out.total.msg << L" out.\r\n"sv;
	std::wcout << timeBuffer << L" | Max msgs in 1 sec: "sv << serverdata.in.highestSec.msg << L" in, "sv << serverdata.out.highestSec.msg << L" out (may be diff seconds).\r\n"sv;
	std::wcout << timeBuffer << L" | Max bytes in 1 sec: "sv << serverdata.in.highestSec.bytes << L" in, "sv << serverdata.out.highestSec.bytes << L" out.\r\n"sv;
	std::wcout << timeBuffer << L" | Press any key to exit.\r\n"sv;

	// Clear input for getchar()
	std::wcin.clear();
	std::wcin.ignore();
	std::wcin.ignore();

	getwchar(); // wait for user keypress

	// Restore console modes
	SetConsoleMode(hStdout, conOrigOutputMode);
	SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), conOrigInputMode);
	SetConsoleTextAttribute(hStdout, conOrigTextAttributes);

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
static bool IsIPTrusted(const char* addr)
{
	// Allow only from LAN addresses, and Darkwire
	return (!strncmp(addr, "10.", sizeof("10.") - 1) || // class A private
		// Class B private is subsection of 172.16.x.x and excluded
		!strncmp(addr, "192.168.1.", sizeof("192.168.1.") - 1) || // class C private
		!strcmp(addr, "127.0.0.1") || // localhost
		!strcmp(addr, "80.229.219.2")); // Darkwire
}

void OnConnectRequest(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> client)
{
	char addr[64];
	lw_addr_prettystring(client->getaddress().data(), addr, sizeof(addr));

	auto banEntry = std::find_if(banIPList.begin(), banIPList.end(), [&](const BanEntry &b) { return b.ip == addr; });
	if (banEntry != banIPList.end())
	{
		if (banEntry->resetAt < _time64(NULL))
			banIPList.erase(banEntry);
		else if (banEntry->disconnects > 3)
		{
			banEntry->resetAt = _time64(NULL) + ((long long)(banEntry->disconnects++ << 2)) * 60LL * 60LL;

			std::wcout << green << L'\r' << timeBuffer << L" | Blocked connection attempt from IP "sv << addr << L", banned due to "sv
				<< UTF8ToWide(banEntry->reason) << L'.'
				<< std::wstring(45, L' ') << L"\r\n"sv << white;
			return server.connect_response(client, banEntry->reason.c_str());
		}
	}

	server.connect_response(client, std::string_view());
	UpdateTitle(server.clientcount());

	std::wcout << green << L'\r' << timeBuffer << L" | New client ID "sv << client->id() << L", IP "sv << addr << L" connected."sv
		<< std::wstring(45, L' ') << L"\r\n"sv << white;
	clientdata.push_back(std::make_unique<clientstats>(client));
}
void OnDisconnect(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> client)
{
	UpdateTitle(server.clientcount());
	std::string name = client->name();
	name = !name.empty() ? name : "[unset]"sv;
	char addr[64];
	lw_addr_prettystring(client->getaddress().data(), addr, sizeof(addr));
	const auto a = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const auto &c) {
		return c->c == client; }
	);

	std::wcout << green << L'\r' << timeBuffer << L" | Client ID "sv << client->id() << L", name "sv << UTF8ToWide(name) << L", IP "sv << UTF8ToWide(addr) << L" disconnected."sv;
	if (a != clientdata.cend())
		std::wcout << L" Uploaded "sv << (**a).total.bytes << L" bytes in "sv << (**a).total.msg << L" msgs total."sv;
	else
		std::wcout << std::wstring(25, L' ');
	std::wcout << L"\r\n"sv << white;

	if (!client->istrusted() && !IsIPTrusted(addr))
	{
		auto banEntry = std::find_if(banIPList.begin(), banIPList.end(), [&](const BanEntry & b) { return b.ip == addr; });
		if (banEntry == banIPList.end())
		{
			std::wcout << yellow << L'\r' << timeBuffer << L" | Due to malformed protocol usage, created a IP ban entry."sv << std::wstring(25, L' ')
				<< L"\r\n"sv << white;
			AddBanEntry(**a, addr, "Broken Lacewing protocol", (_time64(NULL) + 30LL * 60LL));
		}
		else
		{
			std::wcout << yellow << L'\r' << timeBuffer << L" | Due to malformed protocol usage, increased their ban likelihood."sv << std::wstring(25, L' ')
				<< L"\r\n"sv << white;
			++banEntry->disconnects;
		}
	}
	if (a != clientdata.cend())
		clientdata.erase(a);
}

void OnTimerTick(lacewing::timer timer)
{
	std::time_t rawtime = std::time(NULL);
	std::tm timeinfo = { 0 };
	std::time(&rawtime);
	if (!localtime_s(&timeinfo, &rawtime))
		std::wcsftime(timeBuffer, sizeof(timeBuffer), L"%T", &timeinfo);
	else
		wcscpy_s(timeBuffer, sizeof(timeBuffer), L"XX:XX:XX");

	serverdata.in.highestSec.SetToMaxOfCurrentAndThis(serverdata.in.cur);
	serverdata.out.highestSec.SetToMaxOfCurrentAndThis(serverdata.out.cur);
	serverdata.in.total += serverdata.in.cur;
	serverdata.out.total += serverdata.out.cur;
	serverdata.in.lastSec = serverdata.in.cur;
	serverdata.out.lastSec = serverdata.out.cur;
	serverdata.in.cur = serverdata.out.cur = { 0, 0 };

	std::wcout << yellow << timeBuffer << L" | Last sec received "sv << serverdata.in.lastSec.msg << L" messages ("sv << serverdata.in.lastSec.bytes
		<< L" bytes), forwarded "sv << serverdata.out.lastSec.msg << L" ("sv << serverdata.out.lastSec.bytes << L" bytes)."sv
		<< std::wstring(15, L' ') << '\r' << white;
	std::wcout.flush();

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

#ifdef TCP_CLIENT_UPLOAD_CAP
	// open clientdata as shared owner, or disconnect handler's erase may invalidate it while TimerTick is still using it
	for (auto c : clientdata)
	{
		if (!c->exceeded)
			continue;
		char addr[64];
		lw_addr_prettystring(c->c->getaddress().data(), addr, sizeof(addr));

		auto banEntry = std::find_if(banIPList.begin(), banIPList.end(), [&](const BanEntry &b) { return b.ip == addr; });
		if (banEntry == banIPList.end())
			banIPList.push_back(BanEntry(ipAddress, 1, "You have been banned for heavy TCP usage. Contact Phi on Clickteam Discord.", _time64(NULL) + 60LL));
		else
			++banEntry->disconnects;

		std::wcout << red << L'\r' << timeBuffer << L" | Client ID "sv << c->c->id() << L", IP "sv << UTF8ToWide(addr) <<
			L" dropped for heavy TCP upload ("sv << c->cur.bytes << L" bytes in "sv << c->cur.msg << L" msgs)"sv << yellow << L"\r\n"sv;
		c->c->send(1, "You have exceeded the TCP upload limit. Contact Phi on Clickteam Discord."sv, 0);
		c->c->send(0, "You have exceeded the TCP upload limit. Contact Phi on Clickteam Discord."sv, 0);
		c->c->disconnect();

		// disconnect() will usually call disconnect handler, but rarely won't.
		// If it does call the handler, the handler will delete the clientdata "c", so this for loop running through clientdata
		// is now invalid, so we have to break or we get exception from invalid iterator.
		// If it doesn't call the handler, we need to erase "c" or we'll get a disconnect re-attempted every timer tick.
		const auto a = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const auto & ci) {
			return ci->c == c->c; }
		);
		if (a != clientdata.cend())
			clientdata.erase(a);

		break;
	}
#endif
}

static bool shutdowned = false;
void Shutdown()
{
	if (shutdowned)
		return;
	shutdowned = true;

	globalpump->post_eventloop_exit(); // end main loop
}
void OnError(lacewing::relayserver &server, lacewing::error error)
{
	std::string_view err = error->tostring();
	if (err.back() == '.')
		err.remove_suffix(1);
	std::wcout << red << L'\r' << timeBuffer << L" | Error occured: "sv << UTF8ToWide(err) << L". Execution continues."sv
		<< std::wstring(25, L' ') << L"\r\n"sv << white;
}

void OnServerMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	serverdata.in.cur.AddMsg(data.size());

	if constexpr (false)
	{
		std::string name = senderclient->name();
		name = !name.empty() ? name : "[unset]"sv;

		std::wcout << white << L'\r' << timeBuffer << L" | Message from client ID "sv << senderclient->id() << L", name "sv << UTF8ToWide(name)
			<< L":"sv << std::wstring(35, L' ') << L"\r\n"sv
			<< UTF8ToWide(data) << L"\r\n"sv << white;
		std::wcout << white << L'\r' << timeBuffer << L" | blasted = "sv << (blasted ? L"yes"sv : L"no"sv)
			<< L", subchannel = "sv << subchannel << L", variant = "sv << variant
			<< L".\r\n"sv << white;
	}

	if (blasted || variant != 0 || subchannel != 0)
	{
		char addr[64];
		lw_addr_prettystring(senderclient->getaddress().data(), addr, sizeof(addr));
		std::wcout << red << L'\r' << timeBuffer << L" | Dropped server message from IP "sv << UTF8ToWide(addr) << L", invalid type."sv
			<< std::wstring(35, L' ') << L"\r\n"sv << white;
		const auto cd = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const auto &b) { return b->c == senderclient; });
		if (cd != clientdata.cend())
		{
			// Add the final server msg to total
			(**cd).cur.AddMsg(data.size());

			if ((**cd).wastedServerMessages++ > 5)
			{
				auto banEntry = std::find_if(banIPList.begin(), banIPList.end(), [&](const BanEntry& b) { return b.ip == addr; });
				if (banEntry == banIPList.end())
					AddBanEntry(**cd, addr, "Sending too many messages the server is not meant to handle.", _time64(NULL) + 60LL * 60LL);
				else
					++banEntry->disconnects;
				senderclient->send(1, "You have been banned for sending too many server messages that the server is not "
					"designed to receive.\r\nContact Phi on Clickteam Discord."sv);
				senderclient->disconnect();
			}
		}
		return;
	}

	// report channel and server usage
	if (data == "send report"sv || (data.size() > 6 && data.substr(0, 6) == "unban "sv))
	{
		char addr[64];
		lw_addr_prettystring(senderclient->getaddress().data(), addr, sizeof(addr));

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
							lw_addr_prettystring(c->getaddress().data(), addr, 64);
							str << "\u2022 Client \""sv << c->name() << "\", ID "sv << c->id() << ", address \""sv << addr << "\".\n"sv;
							{
								const auto cd = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const auto& b) { return b->c == c; });
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

				str << "\n=== Ban list has "sv << banIPList.size() << " entries:\n"sv;
				if (banIPList.empty())
					str << "  (list empty)"sv;
				else
				{
					std::tm* ptm;
					for (auto& b : banIPList)
					{
						ptm = std::gmtime(&b.resetAt);
						// Format: Mo, 15.06.2009 20:20:00
						std::strftime(addr, sizeof(addr), "%d/%m/%Y %H:%M:%S", ptm);
						str << "\u2022 "sv << b.ip << " : banned until "sv << addr << " GMT, due to \""sv << b.reason
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
					auto banEntry = std::find_if(banIPList.cbegin(), banIPList.cend(), [&](const BanEntry& b) { return b.ip == ipToUnban; });
					if (banEntry == banIPList.cend())
						break;
					banIPList.erase(banEntry);
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

	std::string name = senderclient->name();
	name = !name.empty() ? name : "[unset]"sv;

	std::wcout << white << L'\r' << timeBuffer << L" | Message from client ID "sv << senderclient->id() << L", name "sv << UTF8ToWide(name)
		<< L":"sv << std::wstring(35, L' ') << L"\r\n"sv
		<< UTF8ToWide(data) << L"\r\n"sv << white;
}
bool IncrementClient(std::shared_ptr<lacewing::relayserver::client> client, std::size_t size, bool blasted)
{
	auto cd = std::find_if(clientdata.begin(), clientdata.end(), [&](const auto &b) { return b->c == client; });
	if (cd != clientdata.end())
	{
		(**cd).cur.AddMsg(size);

#ifdef TCP_CLIENT_UPLOAD_CAP
		if (!blasted)
		{
			(**cd).exceeded |= (**cd).cur.bytes > TCP_CLIENT_UPLOAD_CAP;
			return !(**cd).exceeded;
		}
#endif
	}
	return true;
}
void OnPeerMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	std::shared_ptr<lacewing::relayserver::channel> viachannel, std::shared_ptr<lacewing::relayserver::client> receiverclient,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	serverdata.in.cur.AddMsg(data.size());
#ifdef TOTAL_UPLOAD_CAP
	if (blasted && serverdata.out.cur.bytes > TOTAL_UPLOAD_CAP * 4 / 5)
	{
		server.clientmessage_permit(senderclient, viachannel, receiverclient, blasted, subchannel, data, variant, false);
		return;
	}
#endif

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

#ifdef TOTAL_UPLOAD_CAP
	if (blasted && serverdata.out.cur.bytes > TOTAL_UPLOAD_CAP * 4 / 5)
	{
		server.channelmessage_permit(senderclient, channel, blasted, subchannel, data, variant, false);
		return;
	}
#endif

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
	std::wcout << yellow << L'\r' << timeBuffer << L" | "sv << output_wide << std::wstring(35, L' ') << L"\r\n"sv;
	free(output_wide);
	va_end(v);
}

void GenerateFlashPolicy(int port)
{
	char filenameBuf[1024];
	// Get full path of EXE, including EXE filename + ext
	std::size_t bytes = GetModuleFileNameA(NULL, filenameBuf, sizeof(filenameBuf));
	if (bytes == 0U)
	{
		std::wcout << L"Flash policy couldn't be created. Looking up current app folder failed.\r\n"sv;
		return;
	}

	// Strip EXE part
	std::string filename(filenameBuf);
	std::size_t lastSlash = filename.rfind('\\');
	if (lastSlash == std::string::npos)
		lastSlash = filename.rfind('/');
	if (lastSlash == std::string::npos)
	{
		std::wcout << L"Flash policy couldn't be created. Current app folder made no sense.\r\n"sv;
		return;
	}

	filename = filename.substr(0U, lastSlash + 1U) + "FlashPlayerPolicy.xml";

	// File already exists; just use it
	DWORD policyAttr = GetFileAttributesA(filename.c_str());
	if (policyAttr != INVALID_FILE_ATTRIBUTES && !(policyAttr & FILE_ATTRIBUTE_DIRECTORY))
	{
		flashpolicypath = filename;
		return;
	}

	HANDLE forWriting = CreateFileA(filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (forWriting == NULL || forWriting == INVALID_HANDLE_VALUE)
	{
		std::wcout << L"Flash policy couldn't be created. Opening file "sv << UTF8ToWide(filename) << L" for writing in current app folder failed.\r\n"sv;
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
		std::wcout << L"Flash policy couldn't be created. Writing to file "sv << UTF8ToWide(filename) << L" failed.\r\n"sv;
		CloseHandle(forWriting);
		DeleteFileA(filename.c_str());
		return;
	}

	CloseHandle(forWriting);
	flashpolicypath = filename;
}

BOOL WINAPI CloseHandler(DWORD ctrlType)
{
	if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT)
	{
		if (!shutdowned)
		{
			std::wcout << red << L'\r' << timeBuffer << L" | Got Ctrl-C or Close, ending app."sv << std::wstring(70, L' ') << L"\r\n"sv << white;
			Shutdown();
			return true;
		}
	}
	else if (ctrlType == CTRL_BREAK_EVENT)
	{
		std::wcout << red << L'\r' << timeBuffer << L" | Ignoring Ctrl-Break."sv << std::wstring(80, L' ') << L"\r\n"sv << white;
		return true;
	}
	return false;
}

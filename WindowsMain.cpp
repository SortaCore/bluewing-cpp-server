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
#include "ConsoleColors.h"
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
// UDP messages received above this limit will be discarded
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
void UpdateTitle(size_t clientCount);
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
	__time64_t resetAt;
	BanEntry(std::string ip, int disconnects, std::string reason, __time64_t resetAt) :
		ip(ip), disconnects(disconnects), reason(reason), resetAt(resetAt)
	{
		// yay
	}
};
static std::vector<BanEntry> banIPList;

static size_t numMessagesIn = 0, numMessagesOut = 0;
static size_t bytesIn = 0, bytesOut = 0;
struct clientstats
{
	std::shared_ptr<lacewing::relayserver::client> c;
	size_t totalBytesIn;
	size_t totalNumMessagesIn;
	size_t wastedServerMessages;
#ifdef TCP_CLIENT_UPLOAD_CAP
	size_t bytesIn;
	size_t numMessagesIn;
	bool exceeded;
	clientstats(std::shared_ptr<lacewing::relayserver::client> _c) : c(_c), totalBytesIn(0), totalNumMessagesIn(0)
		, bytesIn(0), numMessagesIn(0), exceeded(false), wastedServerMessages(0) {}
#else
	clientstats(std::shared_ptr<lacewing::relayserver::client> _c) : c(_c), totalBytesIn(0), totalNumMessagesIn(0),
		wastedServerMessages(0) {}
#endif
};
static std::vector<std::unique_ptr<clientstats>> clientdata;
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

int ExitWithError(const char * msg, int error)
{
	std::wcout << red << UTF8ToWide(msg) << L", got error number "sv << error << L".\r\n"sv;
	std::wcout << L"Press any key to exit.\r\n"sv;

	// Clear input for getchar()
	std::cin.clear();
	std::cin.ignore();
	std::cin.ignore();

	getchar(); // wait for user keypress
	return 1;
}


int main()
{
	// Enable memory tracking (does nothing in Release)
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	// Handle closing nicely
	SetConsoleCtrlHandler(CloseHandler, TRUE);

	// For Unicode text format
	init_locale();

	// For console text colouring
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	//if (SetConsoleOutputCP(CP_UTF8) == FALSE)
	//	DebugBreak();

#ifdef _lacewing_debug
	FILE * f = NULL;
	if (fopen_s(&f, "Bluewing Server error.log", "w"))
		return ExitWithError("Couldn't open log file", errno);

	if (freopen_s(&f, "CONOUT$", "w", stderr))
	{
		fclose(f);
		return ExitWithError("Couldn't redirect error to log file"sv, errno);
	}
#endif
	// Block some IPs by default
	//banIPList.push_back(BanEntry("75.128.140.10"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, (_time64(NULL) + 24LL * 60LL * 60LL)));
	//banIPList.push_back(BanEntry("127.0.0.1"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, (_time64(NULL) + 24LL * 60LL * 60LL)));

	globalpump = lacewing::eventpump_new();
	globalserver = new lacewing::relayserver(globalpump);
	globalmsgrecvcounttimer = lacewing::timer_new(globalpump);


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

	UpdateTitle(0); // Update console title with 0 clients

	// Check port settings
	int port = FIXEDPORT;
	if constexpr (FIXEDPORT == 0)
	{
		std::wcout << L"Enter port number to begin (default 6121):"sv;

		{
			std::string portStr;
			std::getline(std::cin, portStr);
			std::stringstream lazy(portStr); lazy >> port;
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
		std::wstring(flashpolicypath.empty() ? 30 : 5, L' ') << L"\r\n"sv << yellow;

	globalserver->host(port);

	if (!flashpolicypath.empty())
		globalserver->flash->host(flashpolicypath.c_str());

	// Update messages received/sent line every 1 sec
	globalmsgrecvcounttimer->start(1000L);

	// Start main event loop
	lacewing::error error = nullptr;
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

	// Cleanup time
	clientdata.clear();
	lacewing::timer_delete(globalmsgrecvcounttimer);
	globalserver->unhost();
	globalserver->flash->unhost();
	delete globalserver;
	lacewing::pump_delete(globalpump);

	if (!flashpolicypath.empty() && deleteFlashPolicyAtEndOfApp)
		DeleteFileA(flashpolicypath.c_str());

	// Lacewing uses a sync inside lw_trace, which is singleton and never freed.
	// lw_trace() is a no-op if _lacewing_debug isn't defined.
	// To let garbage collector not see it as a leak:
#if defined(_CRTDBG_MAP_ALLOC) && defined(_lacewing_debug)
	extern lw_sync lw_trace_sync;
	lw_sync_delete(lw_trace_sync);
#endif

	std::wcout << green << timeBuffer << L" | Program completed. Press any key to exit.\r\n"sv;
	// Clear input for getchar()
	std::cin.clear();
	std::cin.ignore();
	std::cin.ignore();

	getchar(); // wait for user keypress

	return 0;
}

void UpdateTitle(size_t clientCount)
{
	size_t channelCount = globalserver->channelcount();
	wchar_t name[128];
	swprintf_s(name, std::size(name), L"Bluewing C++ Server - %zu client%s connected in %zu channel%s",
		clientCount, clientCount == 1 ? L"" : L"s",
		channelCount, channelCount == 1 ? L"" : L"s");
	SetConsoleTitleW(name);
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
				<< std::wstring(45, L' ') << L"\r\n"sv << yellow;
			return server.connect_response(client, banEntry->reason.c_str());
		}
	}

	server.connect_response(client, std::string_view());
	UpdateTitle(server.clientcount());

	std::wcout << green << L'\r' << timeBuffer << L" | New client ID "sv << client->id() << L", IP "sv << addr << L" connected."sv
		<< std::wstring(45, L' ') << L"\r\n"sv << yellow;
	clientdata.push_back(std::make_unique<clientstats>(client));
}
void OnDisconnect(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> client)
{
	UpdateTitle(server.clientcount());
	std::string name = client->name();
	name = !name.empty() ? name : "[unset]"sv;
	char addr[64];
	lw_addr_prettystring(client->getaddress().data(), addr, sizeof(addr));
	auto a = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const std::unique_ptr<clientstats> &c) {
		return c->c == client; }
	);

	std::wcout << green << L'\r' << timeBuffer << L" | Client ID "sv << client->id() << L", name "sv << UTF8ToWide(name) << L", IP "sv << UTF8ToWide(addr) << L" disconnected."sv;
	if (a != clientdata.cend())
		std::wcout << L" Uploaded "sv << (**a).totalBytesIn << L" bytes in "sv << (**a).totalNumMessagesIn << L" msgs total."sv;
	else
		std::wcout << std::wstring(25, L' ');
	std::wcout << L"\r\n"sv << yellow;

	if (a != clientdata.cend())
		clientdata.erase(a);
	if (!client->istrusted())
	{
		auto banEntry = std::find_if(banIPList.begin(), banIPList.end(), [&](const BanEntry & b) { return b.ip == addr; });
		if (banEntry == banIPList.end())
		{
			std::wcout << yellow << L'\r' << timeBuffer << L" | Due to malformed protocol usage, created a IP ban entry."sv << std::wstring(25, L' ')
				<< L"\r\n"sv << yellow;
			banIPList.push_back(BanEntry(addr, 1, "Broken Lacewing protocol", (_time64(NULL) + 30LL * 60LL)));
		}
		else
		{
			std::wcout << yellow << L'\r' << timeBuffer << L" | Due to malformed protocol usage, increased their ban likelihood."sv << std::wstring(25, L' ')
				<< L"\r\n"sv << yellow;
			banEntry->disconnects++;
		}
	}
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

	std::wcout << timeBuffer << L" | Last sec received "sv << numMessagesIn << L" messages ("sv << bytesIn << L" bytes), forwarded "sv
		<< numMessagesOut << L" ("sv << bytesOut << L" bytes)."sv << std::wstring(15, L' ') << '\r';
	numMessagesOut = numMessagesIn = 0U;
	bytesIn = bytesOut = 0U;

#ifdef TCP_CLIENT_UPLOAD_CAP
	for (auto& c : clientdata)
	{
		if (!c->exceeded)
		{
			c->bytesIn = 0;
			c->numMessagesIn = 0;
		}
	}
	for (auto& c : clientdata)
	{
		if (c->exceeded)
		{
			char addr[64];
			const char * ipAddress = c->c->getaddress().data();
			lw_addr_prettystring(ipAddress, addr, sizeof(addr));

			auto banEntry = std::find_if(banIPList.begin(), banIPList.end(), [&](const BanEntry &b) { return b.ip == addr; });
			if (banEntry == banIPList.end())
				banIPList.push_back(BanEntry(ipAddress, 1, "You have been banned for heavy TCP usage. Contact Phi on Clickteam Discord.", _time64(NULL) + 60LL));
			else
				++banEntry->disconnects;

			std::wcout << red << L'\r' << timeBuffer << L" | Client ID "sv << c->c->id() << L", IP "sv << UTF8ToWide(addr) <<
				L" dropped for heavy TCP upload ("sv << c->bytesIn << L" bytes in "sv << c->numMessagesIn << L" msgs)"sv << yellow << L"\r\n"sv;
			c->c->send(1, "You have exceeded the TCP upload limit. Contact Phi on Clickteam Discord."sv, 0);
			c->c->send(0, "You have exceeded the TCP upload limit. Contact Phi on Clickteam Discord."sv, 0);
			c->c->disconnect();

			// disconnect() will usually call disconnect handler, but rarely won't.
			// If it does call the handler, the handler will delete the clientdata "c", so this for loop running through clientdata
			// is now invalid, so we have to break or we get exception from invalid iterator.
			// If it doesn't call the handler, we need to erase "c" or we'll get a disconnect re-attempted every timer tick.
			auto a = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const std::unique_ptr<clientstats> & ci) {
				return ci->c == c->c; }
			);
			if (a != clientdata.cend())
				clientdata.erase(a);

			break;
		}
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
		<< std::wstring(25, L' ') << L"\r\n"sv << yellow;
}

void OnServerMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	++numMessagesIn;
	bytesIn += data.size();

	if (blasted || variant != 0 || subchannel != 0)
	{
		char addr[64];
		lw_addr_prettystring(senderclient->getaddress().data(), addr, sizeof(addr));
		std::wcout << red << L'\r' << timeBuffer << L" | Dropped server message from IP "sv << UTF8ToWide(addr) << L", invalid type."sv
			<< std::wstring(35, L' ') << L"\r\n"sv << yellow;
		auto cd = std::find_if(clientdata.begin(), clientdata.end(), [&](std::unique_ptr<clientstats> &b) { return b->c == senderclient; });
		if (cd != clientdata.end())
		{
			(**cd).totalBytesIn += data.size();
			++(**cd).totalNumMessagesIn;

			if ((**cd).wastedServerMessages++ > 5) {
				banIPList.push_back(BanEntry(addr, 1, "Sending too many messages the server is not meant to handle.",
					_time64(NULL) + 60LL * 60LL));
				senderclient->send(1, "You have been banned for sending too many server messages that the server is not designed to receive.\r\nContact Phi on Clickteam Discord."sv);
				senderclient->disconnect();
			}
		}
		return;
	}
	std::string name = senderclient->name();
	name = !name.empty() ? name : "[unset]"sv;

	std::wcout << white << L'\r' << timeBuffer << L" | Message from client ID "sv << senderclient->id() << L", name "sv << UTF8ToWide(name)
		<< L":"sv << std::wstring(35, L' ') << L"\r\n"sv
		<< UTF8ToWide(data) << L"\r\n"sv << yellow;
}
bool IncrementClient(std::shared_ptr<lacewing::relayserver::client> client, size_t size, bool blasted)
{
	auto cd = std::find_if(clientdata.begin(), clientdata.end(), [&](std::unique_ptr<clientstats> &b) { return b->c == client; });
	if (cd != clientdata.end())
	{
		(**cd).totalBytesIn += size;
		++(**cd).totalNumMessagesIn;

#ifdef TCP_CLIENT_UPLOAD_CAP
		if (!blasted)
		{
			(**cd).bytesIn += size;
			(**cd).exceeded = (**cd).exceeded || (**cd).bytesIn > TCP_CLIENT_UPLOAD_CAP;
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
	++numMessagesIn;
	bytesIn += data.size();
#ifdef TOTAL_UPLOAD_CAP
	if (bytesOut > 50000 && blasted)
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

	++numMessagesOut;
	bytesOut += data.size();
	server.clientmessage_permit(senderclient, viachannel, receiverclient, blasted, subchannel, data, variant, true);
}

void OnChannelMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	std::shared_ptr<lacewing::relayserver::channel> channel,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	++numMessagesIn;
	bytesIn += data.size();

#ifdef TOTAL_UPLOAD_CAP
	if (bytesOut > TOTAL_UPLOAD_CAP && blasted)
	{
		server.channelmessage_permit(senderclient, channel, blasted, subchannel, data, variant, false);
		++numMessagesIn;
		bytesIn += data.size();
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
	size_t numCli = channel->clientcount() - 1U;
	numMessagesOut += numCli;
	bytesOut += numCli * data.size();
}

void GenerateFlashPolicy(int port)
{
	char filenameBuf[1024];
	// Get full path of EXE, including EXE filename + ext
	size_t bytes = GetModuleFileNameA(NULL, filenameBuf, sizeof(filenameBuf));
	if (bytes == 0U)
	{
		std::wcout << L"Flash policy couldn't be created. Looking up current app folder failed.\r\n"sv;
		return;
	}
	// Strip EXE part
	std::string filename(filenameBuf);
	size_t lastSlash = filename.rfind('\\');
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
			std::wcout << red << L'\r' << timeBuffer << L" | Got Ctrl-C or Close, ending app."sv << std::wstring(70, L' ') << L"\r\n"sv << yellow;
			Shutdown();
			return true;
		}
	}
	else if (ctrlType == CTRL_BREAK_EVENT)
	{
		std::wcout << red << L'\r' << timeBuffer << L" | Ignoring Ctrl-Break."sv << std::wstring(80, L' ') << L"\r\n"sv << yellow;
		return true;
	}
	return false;
}

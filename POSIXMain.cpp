/* vim: set noet ts=4 sw=4 sts=4 ft=cpp:
 *
 * Created by Darkwire Software.
 *
 * This example server file is available unlicensed; the MIT license of liblacewing/Lacewing Relay does not apply to this file.
*/

#include <iostream>
#include <ctime>
#include <sstream>
#include <algorithm>
#include <vector>
#include "ConsoleColors.hpp"
#include "Lacewing/Lacewing.h"
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>   // stat
#include <stdbool.h>    // bool type
#include <limits.h>

using namespace std::string_view_literals;


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
void CloseHandler(int sig);

// Global variables
lacewing::eventpump globalpump;
lacewing::timer globalmsgrecvcounttimer;
lacewing::relayserver * globalserver;
std::string flashpolicypath;
bool deleteFlashPolicyAtEndOfApp;
static char timeBuffer[10];

// In case of idiocy
struct BanEntry
{
	std::string ip;
	int disconnects;
	std::string reason;
	std::string chListAtDisconnect;
	time_t resetAt;
	BanEntry(const std::string_view ip, const int disconnects, const std::string_view reason,
		const std::string_view chListAtDisconnect, const time_t resetAt) :
		ip(ip), disconnects(disconnects), reason(reason), chListAtDisconnect(chListAtDisconnect), resetAt(resetAt)
	{
		// yay
	}
};
static std::vector<BanEntry> banIPList;
struct lacestat {
	std::uint64_t msg = 0, bytes = 0;
	lacestat & operator += (const lacestat& s) {
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

static termios oldt;

const char * sslPathCertChain = "./fullchain.pem";
const char * sslPathPrivKey = "./privkey.pem";
void AddBanEntry(const clientstats &c, const char * const addr, const std::string_view msg, const time_t tim)
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

int main()
{
	// Disable console input
	if (tcgetattr(STDIN_FILENO, &oldt) == -1)
	{
		std::cout << "Couldn't read console mode (error "sv << errno << ")."sv;

		if (errno != ENOTTY)
		{
			std::cout << " Aborting server startup.\r\n"sv;
			return errno;
		}
		std::cout << " 25 = not terminal; probably run in simulated terminal. Server startup continues.\r\n"sv;
	}
	termios newt = oldt;
	newt.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	// Handle closing nicely
	signal(SIGABRT, CloseHandler);
	signal(SIGFPE, CloseHandler);
	signal(SIGILL, CloseHandler);
	signal(SIGINT, CloseHandler);
	signal(SIGSEGV, CloseHandler);
	signal(SIGTERM, CloseHandler);

	// We don't use C-style printf(), so desync.
	// It's unclear whether cout or printf is faster; and some say cout is faster only with a fast locale.
	std::ios_base::sync_with_stdio(false);

	// Block some IPs by default
	//banIPList.push_back(BanEntry("127.0.0.1"sv, 4, "IP banned. Contact Phi on Clickteam Discord."sv, std::string_view(), (time(NULL) + 24 * 60 * 60)));

	globalpump = lacewing::eventpump_new();
	globalserver = new lacewing::relayserver(globalpump);
	globalmsgrecvcounttimer = lacewing::timer_new(globalpump, "global message receiving tick-over");
	lacewing::error error = nullptr;

	{
		char message[256];
	#ifdef _DEBUG
		sprintf(message, "This is a Bluewing Server build %i. Currently under debug testing. "
			"You may be disconnected randomly as server is restarted.", lacewing::relayserver::buildnum);
	#elif TCP_CLIENT_UPLOAD_CAP
		sprintf(message, "This is a Bluewing Server build %i. An upload cap is in place. Please pay "
			"attention to Sent server -> peer text messages on subchannels 0 and 1, or you may be banned.",
			lacewing::relayserver::buildnum);
	#else
		sprintf(message, "This is a Bluewing Server build %i.", lacewing::relayserver::buildnum);
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
		std::cout << "Enter port number to begin (default 6121):"sv;

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
	std::cout << green << "Host started. Port "sv << port << ", build "sv << globalserver->buildnum << ". "sv <<
		(flashpolicypath.empty() ? "Flash not hosting"sv : "Flash policy hosting on TCP port 843"sv) << '.' <<
		std::string(flashpolicypath.empty() ? 30 : 5, ' ') << "\r\n"sv << yellow;

	if (websocketSecure)
	{
		if (!lw_file_exists(sslPathCertChain))
		{
			std::cout << yellow << "Couldn't find TLS certficate files - expecting \"fullchain.pem\" and \"privkey.pem\" in app folder.\r\n"
				"Will continue webserver with just insecure websocket.\r\n"sv;
			websocketSecure = 0;
		}
		else if (!globalserver->websocket->load_cert_file(sslPathCertChain, sslPathPrivKey, ""))
		{
			std::cout << red << "Found but couldn't load TLS certificate files \"fullchain.pem\" and \"privkey.pem\". Aborting server.\r\n"sv;
			goto cleanup;
		}
	}

	if (websocketNonSecure || websocketSecure)
	{
		std::cout << green << "WebSocket hosting. Port "sv;
		if (websocketNonSecure)
			std::cout << websocketNonSecure << " (non-secure, ws://xx)"sv;
		if (websocketNonSecure && websocketSecure)
			std::cout << " and port "sv;
		if (websocketSecure)
			std::cout << websocketSecure << " (secure, wss://xx)"sv;
		std::cout << ".\r\n"sv << yellow;
	}
	std::cout.flush();

	globalserver->host((lw_ui16)port);

	if (!flashpolicypath.empty())
		globalserver->flash->host(flashpolicypath.c_str());

	if (websocketNonSecure || websocketSecure)
		globalserver->host_websocket((lw_ui16)websocketNonSecure, (lw_ui16)websocketSecure);

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
		std::cout << red << "\r\n"sv << timeBuffer << " | Error occurred in pump: "sv << error->tostring() << "\r\n"sv;

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
		remove(flashpolicypath.c_str());

	// Lacewing uses a sync inside lw_trace, which is singleton and never freed.
	// lw_trace() is a no-op if _lacewing_debug isn't defined.
	// To let garbage collector not see it as a leak:
#if defined(_CRTDBG_MAP_ALLOC) && defined(_lacewing_debug)
	extern lw_sync lw_trace_sync;
	lw_sync_delete(lw_trace_sync);
#endif

	std::cout << green << timeBuffer << " | Program completed.\r\n"sv;
	std::cout << timeBuffer << " | Total bytes: "sv << serverdata.in.total.bytes << " in, "sv << serverdata.out.total.bytes << " out.\r\n"sv;
	std::cout << timeBuffer << " | Total msgs: "sv << serverdata.in.total.msg << " in, "sv << serverdata.out.total.msg << " out.\r\n"sv;
	std::cout << timeBuffer << " | Max msgs in 1 sec: "sv << serverdata.in.highestSec.msg << " in, "sv << serverdata.out.highestSec.msg << " out (may be diff seconds).\r\n"sv;
	std::cout << timeBuffer << " | Max bytes in 1 sec: "sv << serverdata.in.highestSec.bytes << " in, "sv << serverdata.out.highestSec.bytes << " out.\r\n"sv;
	std::cout << timeBuffer << " | Press any key to exit.\r\n"sv;

	// Clear any keypress the user did before we waited
	std::cin.clear();
	std::cin.ignore();
	std::cin.get(); // wait for user keypress

	std::cout << "\x1B[0m"; // reset console color
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // restore console input mode
	return 0;
}

void UpdateTitle(std::size_t clientCount)
{
	std::size_t channelCount = globalserver->channelcount();
	char name[128];
	sprintf(name, "Bluewing C++ Server - %zu client%s connected in %zu channel%s",
		clientCount, clientCount == 1 ? "" : "s",
		channelCount, channelCount == 1 ? "" : "s");

	// suits aixterm, dtterm, linux, xterm consoles. Taken from .NET Core's Unix terminfo title format string.
	// cygwin: "\x1B];%p1%s\x07";
	// konsole: "\x1B]30;%p1%s\x07";
	// screen: "\x1Bk%p1%s\x1B";
	std::cout << "\033]0;"sv << name << '\007';

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
		if (banEntry->resetAt < time(NULL))
			banIPList.erase(banEntry);
		else if (banEntry->disconnects > 3)
		{
			banEntry->resetAt = time(NULL) + (time_t)(((long long)(banEntry->disconnects++ << 2)) * 60 * 60);

			std::cout << green << '\r' << timeBuffer << " | Blocked connection attempt from IP "sv << addr << ", banned due to "sv
				<< banEntry->reason << '.'
				<< std::string(45, ' ') << "\r\n"sv << yellow;
			return server.connect_response(client, banEntry->reason.c_str());
		}
	}

	server.connect_response(client, std::string_view());
	UpdateTitle(server.clientcount());

	std::cout << green << '\r' << timeBuffer << " | New client ID "sv << client->id() << ", IP "sv << addr << " connected."sv
		<< std::string(45, ' ') << "\r\n"sv << yellow;
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

	std::cout << green << '\r' << timeBuffer << " | Client ID "sv << client->id() << ", name "sv << name << ", IP "sv << addr << " disconnected."sv;
	if (a != clientdata.cend())
		std::cout << " Uploaded "sv << (**a).total.bytes << " bytes in "sv << (**a).total.msg << " msgs total."sv;
	else
		std::cout << std::string(25, ' ');
	std::cout << "\r\n"sv << yellow;

	if (!client->istrusted() && !IsIPTrusted(addr))
	{
		auto banEntry = std::find_if(banIPList.begin(), banIPList.end(), [&](const BanEntry & b) { return b.ip == addr; });
		if (banEntry == banIPList.end())
		{
			std::cout << yellow << '\r' << timeBuffer << " | Due to malformed protocol usage, created a IP ban entry."sv << std::string(25, ' ')
				<< "\r\n"sv << yellow;
			AddBanEntry(**a, addr, "Broken Lacewing protocol", (time(NULL) + 30 * 60));
		}
		else
		{
			std::cout << yellow << '\r' << timeBuffer << " | Due to malformed protocol usage, increased their ban likelihood."sv << std::string(25, ' ')
				<< "\r\n"sv << yellow;
			++banEntry->disconnects;
		}
	}
	if (a != clientdata.cend())
		clientdata.erase(a);
}

void OnTimerTick(lacewing::timer timer)
{
	std::time_t rawtime = std::time(NULL);
	std::time(&rawtime);
	std::tm * timeinfo = localtime(&rawtime);
	if (timeinfo)
		std::strftime(timeBuffer, sizeof(timeBuffer), "%T", timeinfo);
	else
		strcpy(timeBuffer, "XX:XX:XX");

	serverdata.in.highestSec.SetToMaxOfCurrentAndThis(serverdata.in.cur);
	serverdata.out.highestSec.SetToMaxOfCurrentAndThis(serverdata.out.cur);
	serverdata.in.total += serverdata.in.cur;
	serverdata.out.total += serverdata.out.cur;
	serverdata.in.lastSec = serverdata.in.cur;
	serverdata.out.lastSec = serverdata.out.cur;
	serverdata.in.cur = serverdata.out.cur = { 0, 0 };

	std::cout << timeBuffer << " | Last sec received "sv << serverdata.in.lastSec.msg << " messages ("sv << serverdata.in.lastSec.bytes
		<< " bytes), forwarded "sv << serverdata.out.lastSec.msg << " ("sv << serverdata.out.lastSec.bytes << " bytes)."sv
		<< std::string(15, ' ') << '\r' << white;
	std::cout.flush();

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
			AddBanEntry(*c, addr, "You have been banned for heavy TCP usage. Contact Phi on Clickteam Discord.", time(NULL) + 60);
		else
			++banEntry->disconnects;

		std::cout << red << '\r' << timeBuffer << " | Client ID "sv << c->c->id() << ", IP "sv << addr <<
			" dropped for heavy TCP upload ("sv << c->cur.bytes << " bytes in "sv << c->cur.msg << " msgs)"sv << yellow << "\r\n"sv;
		c->c->send(1, "You have exceeded the TCP upload limit. Contact Phi on Clickteam Discord."sv, 0);
		c->c->send(0, "You have exceeded the TCP upload limit. Contact Phi on Clickteam Discord."sv, 0);
		c->c->disconnect();

		// disconnect() will usually call disconnect handler, but rarely won't.
		// If it does call the handler, the handler will delete the clientdata "c", so this for loop running through clientdata
		// is now invalid, so we have to break or we get exception from invalid iterator.
		// If it doesn't call the handler, we need to erase "c" or we'll get a disconnect re-attempted every timer tick.
		const auto a = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const auto & cd) {
			return cd->c == c->c; }
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
	std::cout << red << '\r' << timeBuffer << " | Error occured: "sv << err << ". Execution continues."sv
		<< std::string(25, ' ') << "\r\n"sv << yellow;
}

void OnServerMessage(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> senderclient,
	bool blasted, lw_ui8 subchannel, std::string_view data, lw_ui8 variant)
{
	serverdata.in.cur.AddMsg(data.size());

	if constexpr (false)
	{
		std::string name = senderclient->name();
		name = !name.empty() ? name : "[unset]"sv;

		std::cout << white << '\r' << timeBuffer << " | Message from client ID "sv << senderclient->id() << ", name "sv << name
			<< ":"sv << std::string(35, ' ') << "\r\n"sv
			<< data << "\r\n"sv << white;
		std::cout << white << '\r' << timeBuffer << " | blasted = "sv << (blasted ? "yes"sv : "no"sv)
			<< ", subchannel = "sv << subchannel << ", variant = "sv << variant
			<< ".\r\n"sv << white;
	}

	if (blasted || variant != 0 || subchannel != 0)
	{
		char addr[64];
		lw_addr_prettystring(senderclient->getaddress().data(), addr, sizeof(addr));
		std::cout << red << '\r' << timeBuffer << " | Dropped server message from IP "sv << addr << ", invalid type."sv
			<< std::string(35, ' ') << "\r\n"sv << yellow;
		const auto cd = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const auto &b) { return b->c == senderclient; });
		if (cd != clientdata.end())
		{
			// Add the final server msg to total
			(**cd).cur.AddMsg(data.size());

			if ((**cd).wastedServerMessages++ > 5)
			{
				auto banEntry = std::find_if(banIPList.begin(), banIPList.end(), [&](const BanEntry& b) { return b.ip == addr; });
				if (banEntry == banIPList.end())
					AddBanEntry(**cd, addr, "Sending too many messages the server is not meant to handle.", time(NULL) + 60 * 60);
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
							str << "  \u25E6 Client ID "sv << cli->id() << ", name \""sv << cli->name() << "\"."sv;
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
									str << "  \u25E6 Channel ID "sv << ch->id() << ", \""sv << ch->name() << "\"."sv;
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

	std::cout << white << '\r' << timeBuffer << " | Message from client ID "sv << senderclient->id() << ", name "sv << name
		<< ":"sv << std::string(35, ' ') << "\r\n"sv
		<< data << "\r\n"sv << yellow;
}
bool IncrementClient(std::shared_ptr<lacewing::relayserver::client> client, std::size_t size, bool blasted)
{
	const auto cd = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const auto &b) { return b->c == client; });
	if (cd != clientdata.cend())
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
	int numChars = vsprintf(output, c, v);
	if (numChars <= 0)
		std::abort();
	std::cout << yellow << '\r' << timeBuffer << " | "sv << output << std::string(35, ' ') << "\r\n"sv;
	va_end(v);
}

void GenerateFlashPolicy(int port)
{
	char filenameBuf[1024];
	// Get full path of EXE, including EXE filename + ext
	ssize_t len = ::readlink("/proc/self/exe", filenameBuf, sizeof(filenameBuf) - 1);
	if (len == -1) {
		std::cout << "Flash policy couldn't be created. Looking up current app folder failed.\r\n"sv;
		return;
	}
	filenameBuf[len] = '\0';

	// Strip EXE part
	std::string filename(filenameBuf);
	std::size_t lastSlash = filename.rfind('/');
	if (lastSlash == std::string::npos)
		lastSlash = filename.rfind('\\');
	if (lastSlash == std::string::npos)
	{
		std::cout << "Flash policy couldn't be created. Current app folder made no sense.\r\n"sv;
		return;
	}

	filename = filename.substr(0U, lastSlash + 1U) + "FlashPlayerPolicy.xml";

	// File already exists; just use it
	struct stat buffer;
	if (stat(filename.c_str(), &buffer) == 0)
	{
		flashpolicypath = filename;
		return;
	}

	FILE * forWriting = fopen(filename.c_str(), "wb");
	if (forWriting == NULL)
	{
		std::cout << "Flash policy couldn't be created. Opening file "sv << filename << " for writing in current app folder failed.\r\n"sv;
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
	if (fwrite(policyStr.c_str(), 1, policyStr.size(), forWriting) != policyStr.size())
	{
		std::cout << "Flash policy couldn't be created. Writing to file "sv << filename << " failed.\r\n"sv;
		fclose(forWriting);
		remove(filename.c_str());
		return;
	}

	fclose(forWriting);
	flashpolicypath = filename;
}

void CloseHandler(int sig)
{
	std::cout << red << '\r' << timeBuffer << " | "sv;

	// Catch exceptions
	switch (sig)
	{
	case SIGABRT:
		std::cout << "Caught SIGABRT: usually caused by an abort() or assert()                   \r\n"sv;
		break;
	case SIGFPE:
		std::cout << "Caught SIGFPE: arithmetic exception, such as divide by zero                \r\n"sv;
		break;
	case SIGILL:
		std::cout << "Caught SIGILL: illegal instruction                                         \r\n"sv;
		break;
	case SIGINT:
		std::cout << "Caught SIGINT: interactive attention signal, probably a ctrl+c             \r\n"sv;
		break;
	case SIGSEGV:
		std::cout << "Caught SIGSEGV: segfault                                                   \r\n"sv;
		break;
	case SIGTERM:
	default:
		std::cout << "Caught SIGTERM: a termination request was sent to the program              \r\n"sv;
		break;
	}


	if (!shutdowned)
	{
		std::cout << red << '\r' << timeBuffer << " | Got Ctrl-C or Close, ending the app."sv << std::string(30, ' ') << "\r\n"sv << yellow;
		Shutdown();
	}

	// Every other command will likely kill the program after end of this handler
	if (sig != SIGINT)
	{
		std::cout << red << '\r' << timeBuffer << " | Aborting instantly from signal "sv << sig << '.' << std::string(40, ' ') << "\r\n"sv;
		std::cout << "\x1B[0m"; // reset console color

		tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // restore console input mode

		if (!flashpolicypath.empty() && deleteFlashPolicyAtEndOfApp)
			remove(flashpolicypath.c_str());

		// Cleanup time
		clientdata.clear();
		lacewing::timer_delete(globalmsgrecvcounttimer);
		globalserver->unhost();
		globalserver->flash->unhost();
		globalserver->unhost_websocket(true, true);
		delete globalserver;
		lacewing::pump_delete(globalpump);

		exit(EXIT_FAILURE);
	}
}

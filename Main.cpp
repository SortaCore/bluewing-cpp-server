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

// declare thou
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


void GenerateFlashPolicy(int port);
void Shutdown();
void UpdateTitle(int clientCount);
BOOL WINAPI CloseHandler(DWORD ctrlType);

// global vars (duh)
lacewing::eventpump globalpump;
lacewing::timer globalmsgrecvcounttimer;
lacewing::relayserver * globalserver;
std::string flashpolicypath;
static char timeBuffer[10];

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

// Define if you want Flash hosted. Policy file will automatically be generated.
#define FLASH_ENABLED

// Upload limit for ENTIRE SERVER, TCP + UDP, in bytes
// UDP messages received above this limit will be discarded
// TCP messages received above this limit are still delivered. See TCP_CLIENT_UPLOAD_CAP.
#define TOTAL_UPLOAD_CAP 300000

// TCP upload limit for single clients, per second, in bytes.
// TCP messages received above this limit will send the client an error message
// and disconnect them.
// UDP upload limit is not defined.
#define TCP_CLIENT_UPLOAD_CAP 3000

// Set this to 0 for the app to ask the user what port it is, on bootup;
// or to another number to use that by default
static const int FIXEDPORT = 6121;

int ExitWithError(const char * msg, int error)
{
	std::cout << red << msg << ", got error number " << error << ".\r\n";
	std::cout << "Press any key to exit.\r\n";

	// Clear input for getchar()
	std::cin.clear();
	std::cin.ignore();
	std::cin.ignore();

	getchar(); // wait for user keypress
	return 1;
}

int main()
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	SetConsoleCtrlHandler(CloseHandler, TRUE);

	// for colouring
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
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
	//banIPList.push_back(BanEntry("75.128.140.10", 3, "IP banned. Contact Phi on Clickteam Discord.", (_time64(NULL) + 24LL * 60LL * 60LL)));
	//banIPList.push_back(BanEntry("127.0.0.1", 3, "IP banned. Contact Phi on Clickteam Discord.", (_time64(NULL) + 24LL * 60LL * 60LL)));

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

	UpdateTitle(0); // Update console title with 0 clients

	// Check port settings
	int port = FIXEDPORT;
	if (port == 0)
	{
		std::cout << "Enter port number to begin (default 6121):";

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

	// Host the thing
	std::cout << green << "Host started. Port " << port << ", build " << globalserver->buildnum << ". " << 
		(flashpolicypath.empty() ? "Flash not hosting" : "Flash policy hosting on TCP port 843") << ".\r\n" << yellow;
	
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
	{
		std::cout << red << "\r\n" << timeBuffer << " | Error occurred in pump: " << error->tostring() << "\r\n";

#ifdef _DEBUG
		// Clear input for getchar()
		std::cin.clear();
		std::cin.ignore();
		std::cin.ignore();
		getchar(); // wait for user keypress
#endif
	}

	// Cleanup time
	lacewing::timer_delete(globalmsgrecvcounttimer);
	delete globalserver;
	lacewing::pump_delete(globalpump);

	if (!flashpolicypath.empty())
		DeleteFileA(flashpolicypath.c_str());

	// [Phi] I did track down some nasty leaks earlier but confirmed no problem now
#ifdef _CRTDBG_MAP_ALLOC
	std::cout << green << timeBuffer << " | Program completed. Press any key to dump memory.\r\n";
	// Clear input for getchar()
	std::cin.clear();
	std::cin.ignore();
	std::cin.ignore();

	globalmsgrecvcounttimer = nullptr;
	globalserver = nullptr;
	globalpump = nullptr;
	_CrtDumpMemoryLeaks();
#endif

	std::cout << green << timeBuffer << " | Program completed. Press any key to exit.\r\n";
	// Clear input for getchar()
	std::cin.clear();
	std::cin.ignore();
	std::cin.ignore(); 

	getchar(); // wait for user keypress

	return 0;
}

void UpdateTitle(int clientCount)
{
	size_t channelCount = globalserver->channelcount();
	char name[128];
	sprintf_s(name, sizeof(name), "Bluewing C++ Server - %u client%s connected in %u channel%s",
		clientCount, clientCount == 1 ? "" : "s", 
		channelCount, channelCount == 1 ? "" : "s");
	SetConsoleTitleA(name);
}

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
	clientstats(lacewing::relayserver::client * _c) : c(_c), totalBytesIn(0), totalNumMessagesIn(0),
		wastedServerMessages(0) {}
#endif
};
static std::vector<std::unique_ptr<clientstats>> clientdata;
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
			banEntry->resetAt = _time64(NULL) + (banEntry->disconnects++ << 2) * 60LL * 60LL;

			std::cout << green << "\r" << timeBuffer << " | Blocked client from IP " << addr << " was dropped."
				<< std::string(45, ' ') << "\r\n" << yellow;
			return server.connect_response(client, banEntry->reason.c_str());
		}
	}

	server.connect_response(client, nullptr);
	UpdateTitle(server.clientcount());

	std::cout << green << "\r" << timeBuffer << " | New client ID " << client->id() << ", IP " << addr << " connected." 
		<< std::string(45, ' ') << "\r\n" << yellow;
	clientdata.push_back(std::make_unique<clientstats>(client));
}
void OnDisconnect(lacewing::relayserver &server, std::shared_ptr<lacewing::relayserver::client> client)
{
	UpdateTitle(server.clientcount());
	std::string name = client->name();
	name = !name.empty() ? name : "[unset]";
	char addr[64];
	lw_addr_prettystring(client->getaddress().data(), addr, sizeof(addr));
	auto a = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](const std::unique_ptr<clientstats> &c) {
		return c->c == client; }
	);

	std::cout << green << "\r" << timeBuffer << " | Client ID " << client->id() << ", name " << name << ", IP " << addr << " disconnected.";
	if (a != clientdata.cend())
		std::cout << " Uploaded " << (**a).totalBytesIn << " bytes in " << (**a).totalNumMessagesIn << " msgs total.";
	else
		std::cout << std::string(25, ' ');
	std::cout << "\r\n" << yellow;

	if (a != clientdata.cend())
		clientdata.erase(a);
}

void OnTimerTick(lacewing::timer timer)
{
	std::time_t rawtime = std::time(NULL);
	std::tm timeinfo = { 0 };
	std::time(&rawtime);
	if (!localtime_s(&timeinfo, &rawtime))
		std::strftime(timeBuffer, sizeof(timeBuffer), "%T", &timeinfo);
	else
		strcpy_s(timeBuffer, sizeof(timeBuffer), "XX:XX:XX");

	std::cout << timeBuffer << " | Last sec received " << numMessagesIn << " messages (" << bytesIn << " bytes), forwarded " 
		<< numMessagesOut << " (" << bytesOut << " bytes)." << std::string(15, ' ') << "\r";
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

			std::cout << red << "\r" << timeBuffer << " | Client ID " << c->c->id() << ", IP " << addr <<
				" dropped for heavy TCP upload (" << c->bytesIn << " bytes in " << c->numMessagesIn << " msgs)" << yellow << "\r\n";
			c->c->send(1, "You have exceeded the TCP upload limit. Contact Phi on Clickteam Discord.", 0);
			c->c->send(0, "You have exceeded the TCP upload limit. Contact Phi on Clickteam Discord.", 0);
			c->c->disconnect();

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
	
	globalmsgrecvcounttimer->stop();
	globalpump->post_eventloop_exit(); // end main loop
}
void OnError(lacewing::relayserver &server, lacewing::error error)
{
	std::cout << red << "\r" << timeBuffer << " | Error occured: " << error->tostring() << ". Execution continues."
		<< std::string(25, ' ') << "\r\n" << yellow;
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
		std::cout << red << "\r" << timeBuffer << " | Dropped server message from IP " << addr << ", invalid type."
			<< std::string(35, ' ') << "\r\n" << yellow;
		auto cd = std::find_if(clientdata.begin(), clientdata.end(), [&](std::unique_ptr<clientstats> &b) { return b->c == senderclient; });
		if (cd != clientdata.end())
		{
			(**cd).totalBytesIn += data.size();
			++(**cd).totalNumMessagesIn;

			if ((**cd).wastedServerMessages++ > 5) {
				banIPList.push_back(BanEntry(addr, 1, "Sending too many messages the server is not meant to handle.",
					_time64(NULL) + 60LL * 60LL));
				senderclient->send(1, "You have been banned for sending too many server messages that the server is not designed to receive.\r\nContact Phi on Clickteam Discord.");
				senderclient->disconnect();
			}
		}
		return;
	}
	std::string name = senderclient->name();
	name = !name.empty() ? name : "[unset]";

	std::cout << white << "\r" << timeBuffer << " | Message from client ID " << senderclient->id() << ", name " << name 
		<< ":" << std::string(35, ' ') << "\r\n"
		<< data << "\r\n" << yellow;
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
	std::stringstream flashPolicy;
	flashPolicy << "<?xml version=\"1.0\"?>\r\n"
		"<!DOCTYPE cross-domain-policy SYSTEM \"/xml/dtds/cross-domain-policy.dtd\">\r\n"
		"<cross-domain-policy>\r\n"
		"\t<site-control permitted-cross-domain-policies=\"master-only\"/>\r\n"
		"\t<allow-access-from domain=\"*\" to-ports=\"843," << port << ",583\" secure=\"false\" />\r\n"
		"</cross-domain-policy>";

	char filenameBuf[1024];
	// Get full path of EXE, including EXE filename + ext
	size_t bytes = GetModuleFileNameA(NULL, filenameBuf, sizeof(filenameBuf));
	if (bytes == 0U)
	{
		std::cout << "Flash policy couldn't be created. Looking up current app folder failed.\r\n";
		return;
	}
	// Strip EXE part
	std::string filename(filenameBuf);
	size_t lastSlash = filename.rfind('\\');
	if (lastSlash == std::string::npos)
		lastSlash = filename.rfind('/');
	if (lastSlash == std::string::npos)
	{
		std::cout << "Flash policy couldn't be created. Current app folder made no sense.\r\n";
		return;
	}

	filename = filename.substr(0U, lastSlash + 1U) + "FlashPlayerPolicy.xml";
	HANDLE forWriting = CreateFileA(filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (forWriting == NULL || forWriting == INVALID_HANDLE_VALUE)
	{
		std::cout << "Flash policy couldn't be created. Opening file " << filename << " for writing in current app folder failed.\r\n";
		return;
	}

	std::string policyStr = flashPolicy.str();

	if (!WriteFile(forWriting, policyStr.c_str(), policyStr.size(), NULL, NULL))
	{
		std::cout << "Flash policy couldn't be created. Writing to file " << filename << " failed.\r\n";
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
			std::cout << red << "\r" << timeBuffer << " | Got Ctrl-C or Close, ending app." << std::string(70, ' ') << "\r\n" << yellow;
			Shutdown();
			return true;
		}
	}
	else if (ctrlType == CTRL_BREAK_EVENT)
	{
		std::cout << red << "\r" << timeBuffer << " | Ignoring Ctrl-Break." << std::string(80, ' ') << "\r\n" << yellow;
		return true;
	}
	return false;
}

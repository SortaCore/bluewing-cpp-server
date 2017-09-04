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
void OnConnectRequest(lacewing::relayserver &server, lacewing::relayserver::client &client);
void OnDisconnect(lacewing::relayserver &server, lacewing::relayserver::client &client);
void OnTimerTick(lacewing::timer timer);
void OnError(lacewing::relayserver &server, lacewing::error error);
void OnServerMessage(lacewing::relayserver &server, lacewing::relayserver::client &senderclient,
	bool blasted, int subchannel, const char * data, size_t size, int variant);
void OnChannelMessage(lacewing::relayserver &server, lacewing::relayserver::client &senderclient,
	lacewing::relayserver::channel &channel,
	bool blasted, int subchannel, const char * data, size_t size, int variant);
void OnPeerMessage(lacewing::relayserver &server, lacewing::relayserver::client &senderclient,
	lacewing::relayserver::channel &viachannel, lacewing::relayserver::client &receiverclient,
	bool blasted, int subchannel, const char * data, size_t size, int variant);


void GenerateFlashPolicy(int port);
void Shutdown();
void UpdateTitle(int clientCount);
BOOL WINAPI CloseHandler(DWORD ctrlType);

// global vars (duh)
lacewing::eventpump globalpump;
lacewing::timer globalmsgrecvcounttimer;
lacewing::relayserver * globalserver;
std::string flashpolicypath;

// Define if you want Flash hosted. Policy file will automatically be generated.
#define FLASH_ENABLED

// Upload limit for ENTIRE SERVER, TCP + UDP, in bytes
// UDP messages received above this limit will be discarded
// TCP messages received above this limit are still delivered. See TCP_CLIENT_UPLOAD_CAP.
// #define TOTAL_UPLOAD_CAP 30000

// TCP upload limit for single clients, per second, in bytes.
// TCP messages received above this limit will send the client an error message
// and disconnect them.
// UDP upload limit is not defined.
// #define TCP_CLIENT_UPLOAD_CAP 1536

// Set this to 0 for the app to ask the user what port it is, on bootup;
// or to another number to use that by default
static const int FIXEDPORT = 6121;

int main()
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	SetConsoleCtrlHandler(CloseHandler, TRUE);

	// for colouring
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
#ifdef _lacewing_debug
	freopen("Bluewing Server error.log", "w", stderr);
#endif

	globalpump = lacewing::eventpump_new();
	globalserver = new lacewing::relayserver(globalpump);
	globalmsgrecvcounttimer = lacewing::timer_new(globalpump);

	{
		char * message = (char *)alloca(256U);
	#ifdef _DEBUG
		sprintf_s(message, 256, "This is a Bluewing Server build %i. Currently under debug testing. "
			"You may be disconnected randomly as server is restarted.", lacewing::relayserver::buildnum);
	#else
		sprintf_s(message, 256, "This is a Bluewing Server build %i.", lacewing::relayserver::buildnum);
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
		std::cout << red << "\r\nError occurred in pump: " << error->tostring() << "\r\n";

		// Clear input for getchar()
		std::cin.clear();
		std::cin.ignore();
		std::cin.ignore();

		getchar(); // wait for user keypress
	}

	// Cleanup time
	lacewing::timer_delete(globalmsgrecvcounttimer);
	delete globalserver;
	lacewing::pump_delete(globalpump);

	if (!flashpolicypath.empty())
		DeleteFileA(flashpolicypath.c_str());

	// [Phi] I did track down some nasty leaks earlier but confirmed no problem now
#ifdef _CRTDBG_MAP_ALLOC
	std::cout << green << "Program completed. Press any key to dump memory.\r\n";
	// Clear input for getchar()
	std::cin.clear();
	std::cin.ignore();
	std::cin.ignore();

	globalmsgrecvcounttimer = nullptr;
	globalserver = nullptr;
	globalpump = nullptr;
	_CrtDumpMemoryLeaks();
#endif

	std::cout << green << "Program completed. Press any key to exit.\r\n";
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
static char buffer[10];
static size_t numMessagesIn = 0, numMessagesOut = 0;
static size_t bytesIn = 0, bytesOut = 0;
struct clientstats
{
	lacewing::relayserver::client * c;
	size_t totalBytesIn;
	size_t totalNumMessagesIn;
#ifdef TCP_CLIENT_UPLOAD_CAP
	size_t bytesIn;
	size_t numMessagesIn;
	bool exceeded;
	clientstats(lacewing::relayserver::client * _c) : c(_c), totalBytesIn(0), totalNumMessagesIn(0)
		, bytesIn(0), numMessagesIn(0), exceeded(false) {}
#else
	clientstats(lacewing::relayserver::client * _c) : c(_c), totalBytesIn(0), totalNumMessagesIn(0) {}
#endif
};
static std::vector<clientstats *> clientdata;
void OnConnectRequest(lacewing::relayserver &server, lacewing::relayserver::client &client)
{
	server.connect_response(client, nullptr);
	UpdateTitle(server.clientcount());

	char addr[64];
	lacewing::lw_addr_prettystring(client.getaddress(), addr, 64);
	std::cout << green << "\r" << buffer << " | New client ID " << client.id() << ", IP " << addr << " connected." 
		<< std::string(45, ' ') << "\r\n" << yellow;
	clientdata.push_back(new clientstats(&client));
}
void OnDisconnect(lacewing::relayserver &server, lacewing::relayserver::client &client)
{
	UpdateTitle(server.clientcount());
	const char * name = client.name();
	name = name ? name : "[unset]";
	char addr[64];
	lacewing::lw_addr_prettystring(client.getaddress(), addr, 64);
	auto a = std::find_if(clientdata.cbegin(), clientdata.cend(), [&](clientstats *const &c) {
		return c->c == &client; }
	);

	std::cout << green << "\r" << buffer << " | Client ID " << client.id() << ", name " << name << ", IP " << addr << " disconnected.";
	if (a != clientdata.cend())
		std::cout << " Uploaded " << (**a).totalBytesIn << " bytes in " << (**a).totalNumMessagesIn << " msgs total.";
	else
		std::cout << std::string(25, ' ');
	std::cout << "\r\n" << yellow;

	if (a != clientdata.cend())
	{
		delete (*a);
		clientdata.erase(a);
	}
}

void OnTimerTick(lacewing::timer timer)
{
	std::time_t rawtime = std::time(NULL);
	std::tm timeinfo = { 0 };
	std::time(&rawtime);
	if (!localtime_s(&timeinfo, &rawtime))
		std::strftime(buffer, sizeof(buffer), "%T", &timeinfo);
	else
		strcpy_s(buffer, sizeof(buffer), "XX:XX:XX");

	std::cout << buffer << " | Last sec received " << numMessagesIn << " messages (" << bytesIn << " bytes), forwarded " 
		<< numMessagesOut << " (" << bytesOut << " bytes)." << std::string(15, ' ') << "\r";
	numMessagesOut = numMessagesIn = 0U;
	bytesIn = bytesOut = 0U;

#ifdef TCP_CLIENT_UPLOAD_CAP
	for (auto c : clientdata)
	{
		if (!c->exceeded)
		{
			c->bytesIn = 0;
			c->numMessagesIn = 0;
		}
	}
	for (auto c : clientdata)
	{
		if (c->exceeded)
		{
			std::cout << red << "\r" << buffer << " | Client ID " << c->c->id() << ", IP " << c->c->getaddress() <<
				" dropped for heavy TCP upload (" << c->bytesIn << " bytes in " << c->numMessagesIn << " msgs)" << yellow << "\r\n";
			c->c->send(1, "You have exceeded the TCP upload limit. Please contact Phi on Clickteam Discord.", 80, 0);
			c->c->send(0, "You have exceeded the TCP upload limit. Please contact Phi on Clickteam Discord.", 80, 0);
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
	std::cout << red << "\r" << buffer << " | Error occured: " << error->tostring() << ". Execution continues."
		<< std::string(25, ' ') << "\r\n" << yellow;
}

void OnServerMessage(lacewing::relayserver &server, lacewing::relayserver::client &senderclient,
	bool blasted, int subchannel, const char * data, size_t size, int variant)
{
	++numMessagesIn;
	bytesIn += size;

	if (blasted || variant != 0 || subchannel != 0)
	{
		std::cout << red << "\r" << buffer << " | Dropped server message, invalid type."
			<< std::string(35, ' ') << "\r\n" << yellow;
		return;
	}
	const char * name = senderclient.name();
	name = name ? name : "[unset]";

	std::cout << white << "\r" << buffer << " | Message from client ID " << senderclient.id() << ", name " << name 
		<< ":" << std::string(35, ' ') << "\r\n"
		<< std::string(data, size) << "\r\n" << yellow;
}
bool IncrementClient(lacewing::relayserver::client &client, size_t size, bool blasted)
{
	auto cd = std::find_if(clientdata.begin(), clientdata.end(), [&](clientstats *&b) { return b->c == &client; });
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
void OnPeerMessage(lacewing::relayserver &server, lacewing::relayserver::client &senderclient,
	lacewing::relayserver::channel &viachannel, lacewing::relayserver::client &receiverclient,
	bool blasted, int subchannel, const char * data, size_t size, int variant)
{
	++numMessagesIn;
	bytesIn += size;
#ifdef TOTAL_UPLOAD_CAP
	if (bytesOut > 50000 && blasted)
	{
		server.clientmessage_permit(senderclient, viachannel, receiverclient, blasted, subchannel, data, size, variant, false);
		return;
	}
#endif

	// False means it's exceeded TCP limits (if TCP limit is off, this'll always return true)
	if (!IncrementClient(senderclient, size, blasted))
	{
		server.clientmessage_permit(senderclient, viachannel, receiverclient, blasted, subchannel, data, size, variant, false);
		return;
	}

	++numMessagesOut;
	bytesOut += size;
	server.clientmessage_permit(senderclient, viachannel, receiverclient, blasted, subchannel, data, size, variant, true);
}

void OnChannelMessage(lacewing::relayserver &server, lacewing::relayserver::client &senderclient,
	lacewing::relayserver::channel &channel,
	bool blasted, int subchannel, const char * data, size_t size, int variant)
{
	++numMessagesIn;
	bytesIn += size;

#ifdef TOTAL_UPLOAD_CAP
	if (bytesOut > TOTAL_UPLOAD_CAP && blasted)
	{
		server.channelmessage_permit(senderclient, channel, blasted, subchannel, data, size, variant, false);
		++numMessagesIn;
		bytesIn += size;
		return;
	}
#endif

	// False means it's exceeded TCP limits (if TCP limit is off, this'll always return true)
	if (!IncrementClient(senderclient, size, blasted))
	{
		server.channelmessage_permit(senderclient, channel, blasted, subchannel, data, size, variant, false);
		return;
	}

	server.channelmessage_permit(senderclient, channel, blasted, subchannel, data, size, variant, true);
	size_t numCli = channel.clientcount() - 1U;
	numMessagesOut += numCli;
	bytesOut += numCli * size;
}

void GenerateFlashPolicy(int port)
{
	std::stringstream flashPolicy;	flashPolicy << "<?xml version=\"1.0\"?>\r\n"		"<!DOCTYPE cross-domain-policy SYSTEM \"/xml/dtds/cross-domain-policy.dtd\">\r\n"		"<cross-domain-policy>\r\n"		"\t<site-control permitted-cross-domain-policies=\"master-only\"/>\r\n"		"\t<allow-access-from domain=\"*\" to-ports=\"843," << port << ",583\" secure=\"false\" />\r\n"		"</cross-domain-policy>";

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
			std::cout << red << "\r" << buffer << " | Got Ctrl-C or Close, ending app." << std::string(70, ' ') << "\r\n" << yellow;
			Shutdown();
			return true;
		}
	}
	else if (ctrlType == CTRL_BREAK_EVENT)
	{
		std::cout << red << "\r" << buffer << " | Ignoring Ctrl-Break." << std::string(80, ' ') << "\r\n" << yellow;
		return true;
	}
	return false;
}

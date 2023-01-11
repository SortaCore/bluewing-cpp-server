# bluewing-cpp-server
An example of Lacewing Blue (Bluewing) implementation of Lacewing Relay protocol as a server.  
Windows EXE and Unix executable using Visual Studio. Full C++ speed, with no trace of Clickteam Fusion.  
Windows EXE is in x86 and x64. Unix is in x86 (i386), x64 (x86_64), ARMv7 and ARM64.


# Features
* This server is compatible with clients that use Lacewing Relay protocol.
* Optional Flash policy hosting, and auto-generates a policy file for the Lacewing port.
* Optional upload cap on TCP + UDP for all clients, and TCP for clients.
* This server is compatible with HTML5 and UWP JavaScript, both secure and insecure WebSocket.  
To use the WebSocket Secure server, ensure you have privkey.pem and fullchain.pem in the app folder.


# This server's Fusion client compatibility
The server is compatible with any of the following (and any combination):
* non-Fusion clients
* client programs that are made in Clickteam Fusion 2.5 or Multimedia Fusion 2.0
* Fusion 2.0/2.5 clients for Windows, Android, iOS, SWF/Flash, HTML5, and UWP
* Lacewing Relay and Lacewing Blue Fusion extensions (Blue is highly recommended for client, as it is more recent)

# Tools needed to edit this source
You will need Visual Studio 2017+, with Windows XP support add-on.
* To add it to your VS install, run the Visual Studio Installer, select More > Modify, and under Individual Components tab, enable C++ Windows XP Support for VS 2017 (v141) tools.  
(Note that VS 2017 XP is the latest XP, so you want VS 2017 XP support even if you're using VS 2019.)
* Alternatively, XP support requirement can be removed in half a minute; simply switch the compiler under Project Properties > General > Platform Toolset, from v141_xp to v121 (if you're using VS 2017) or to v141 (if VS 2019).

Due to use of C++17 features, like std::string_view, VS 2015 is not supported.

# Multi-platform note
While this repository is a Visual Studio and Windows based server, Blue liblacewing should be usable on other compilers (e.g. GCC) and on other POSIX-based platforms (e.g. Linux flavours). If you get any issues compiling Bluewing itself on non-Windows, or using non-Visual Studio, feel free to create an issue or pull request.

# License
This is **MIT license**, so you're free to use personally, commercially, or sell your variant of this, but you should include a notice that you retrieved it from this repository.

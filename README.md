# bluewing-cpp-server
An example of Lacewing Blue (Bluewing) implementation of Lacewing Relay protocol as a server.
Windows EXE using Visual Studio. Full C++ speed, with no trace of Clickteam Fusion.
Bluewing Server Full Powah!

# Multi-platform note
While this repository is a Visual Studio and Windows based server, Blue liblacewing should be usable on other compilers (e.g. GCC) and on other POSIX-based platforms (e.g. Linux flavours). If you get any issues compiling Bluewing itself on non-Windows, or using non-Visual Studio, feel free to create an issue or pull request.

# License
This is **MIT license**, so you're free to use personally, commercially, or sell your variant of this, but you should include a notice that you retrieved it from this repository.

# Features
* This server is compatible with clients that use Lacewing Relay protocol.
* Optional Flash policy hosting, and auto-generates a policy file for the Lacewing port.
* Optional upload cap on TCP + UDP for all clients, and TCP for clients.

This server is NOT compatible with HTML5. There is no HTML5 server for Lacewing as of this writing, so it is not compatible.

# This server's Fusion client compatibility
The server is compatible with any of the following (and any combination):
* non-Fusion clients
* client programs that are made in Clickteam Fusion 2.5 or Multimedia Fusion 2.0
* Fusion 2.0/2.5 clients for Windows, Android, and SWF/Flash
* Lacewing Relay and Lacewing Blue Fusion extensions (Blue is highly recommended for client, as it is more recent)

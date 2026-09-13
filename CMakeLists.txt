cmake_minimum_required(VERSION 3.10)

project(bluewing-cpp-server LANGUAGES C CXX)

# If CMake is earlier than 3.13, then target_link_options doesn't exist,
# define a limited shim
if(NOT COMMAND target_link_options)
    function(target_link_options target scope)
        if(NOT scope STREQUAL "PRIVATE")
            message(FATAL_ERROR
                "Compatibility target_link_options only supports PRIVATE"
            )
        endif()

        # LINK_FLAGS is one command-line string, unlike target_link_options'
        # list-valued interface.  Convert CMake's list separators so Ninja
        # does not pass literal semicolons to the shell.
        string(REPLACE ";" " " link_flags "${ARGN}")
        set_property(TARGET ${target} APPEND_STRING
            PROPERTY LINK_FLAGS " ${link_flags}"
        )
    endfunction()
endif()

include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckFunctionExists)

option(ENABLE_CXX "Enable the Lacewing C++ API" ON)
option(ENABLE_THREADS "Enable thread support" ON)

set(ENABLE_SSL_DEFAULT OFF)
if(UNIX)
    find_package(OpenSSL QUIET)
    if(OPENSSL_FOUND)
        set(ENABLE_SSL_DEFAULT ON)
    endif()
endif()
option(ENABLE_SSL "Enable SSL support" ${ENABLE_SSL_DEFAULT})
unset(ENABLE_SSL_DEFAULT)

set(BLUEWING_CONSOLE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

if(NOT ENABLE_CXX)
    message(FATAL_ERROR "bluewing-cpp-server requires ENABLE_CXX because RelayServer and the console use the Lacewing C++ API")
endif()

# Keep a compilation database beside non-Visual-Studio build trees.
if(NOT CMAKE_GENERATOR MATCHES "^Visual Studio")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

set(BLUEWING_COMMON_SOURCES
    Lacewing/CodePointAllowList.cpp
    Lacewing/deps/http-parser/http_parser.c
    Lacewing/deps/multipart-parser/multipart_parser.c
    Lacewing/deps/utf8proc.c
    Lacewing/deps/utf8proc_data.c
    Lacewing/PhiAddress.cc
    Lacewing/ReadWriteLock.cc
    Lacewing/RelayServer.cc
    Lacewing/src/address.c
    Lacewing/src/error.c
    Lacewing/src/filter.c
    Lacewing/src/flashpolicy.c
    Lacewing/src/global.c
    Lacewing/src/heapbuffer.c
    Lacewing/src/list.c
    Lacewing/src/nvhash.c
    Lacewing/src/pipe.c
    Lacewing/src/pump.c
    Lacewing/src/refcount-dbg.c
    Lacewing/src/stream.c
    Lacewing/src/streamgraph.c
    Lacewing/src/util.c
    Lacewing/src/webserver/http/http-client.c
    Lacewing/src/webserver/http/http-parse.c
    Lacewing/src/webserver/mimetypes.c
    Lacewing/src/webserver/multipart.c
    Lacewing/src/webserver/request.c
    Lacewing/src/webserver/sessions.c
    Lacewing/src/webserver/upload.c
    Lacewing/src/webserver/webserver.c
)

if(ENABLE_CXX)
    list(APPEND BLUEWING_COMMON_SOURCES
        Lacewing/src/cxx/address2.cc
        Lacewing/src/cxx/client2.cc
        Lacewing/src/cxx/error2.cc
        Lacewing/src/cxx/event2.cc
        Lacewing/src/cxx/eventpump2.cc
        Lacewing/src/cxx/fdstream2.cc
        Lacewing/src/cxx/file2.cc
        Lacewing/src/cxx/filter2.cc
        Lacewing/src/cxx/flashpolicy2.cc
        Lacewing/src/cxx/pipe2.cc
        Lacewing/src/cxx/pump2.cc
        Lacewing/src/cxx/server2.cc
        Lacewing/src/cxx/stream2.cc
        Lacewing/src/cxx/sync2.cc
        Lacewing/src/cxx/thread2.cc
        Lacewing/src/cxx/timer2.cc
        Lacewing/src/cxx/udp2.cc
        Lacewing/src/cxx/webserver2.cc
    )
endif()

set(BLUEWING_PLATFORM_DEFINITIONS)
set(BLUEWING_PLATFORM_LIBRARIES)

if(WIN32)
    set(BLUEWING_PROJECT_NAME bluewing-cpp-server)
    option(BLUEWING_WINDOWS_UTF8_CONSOLE
        "Use the modern UTF-8 Windows console instead of the legacy UTF-16 console" ON)

    if(BLUEWING_WINDOWS_UTF8_CONSOLE)
        set(BLUEWING_CONSOLE_SOURCE "${BLUEWING_CONSOLE_SOURCE_DIR}/WindowsUTF8Console.cpp")
    else()
        set(BLUEWING_CONSOLE_SOURCE "${BLUEWING_CONSOLE_SOURCE_DIR}/WindowsWideConsole.cpp")
        list(APPEND BLUEWING_PLATFORM_DEFINITIONS _UNICODE UNICODE)
    endif()

    set(BLUEWING_PLATFORM_SOURCES
        Lacewing/src/windows/client.c
        Lacewing/src/windows/compat.c
        Lacewing/src/windows/event.c
        Lacewing/src/windows/eventpump.c
        Lacewing/src/windows/fdstream.c
        Lacewing/src/windows/file.c
        Lacewing/src/windows/global2.c
        Lacewing/src/windows/server.c
        Lacewing/src/windows/ssl/serverssl.c
        Lacewing/src/windows/ssl/ssl.c
        Lacewing/src/windows/sync.c
        Lacewing/src/windows/thread.c
        Lacewing/src/windows/timer.c
        Lacewing/src/windows/udp.c
    )

    list(APPEND BLUEWING_PLATFORM_LIBRARIES
        ws2_32 mswsock mpr secur32 crypt32 iphlpapi
    )
elseif(UNIX)
    set(BLUEWING_PROJECT_NAME bluewing-cpp-server-linux)
    set(BLUEWING_CONSOLE_SOURCE "${BLUEWING_CONSOLE_SOURCE_DIR}/LinuxConsole.cpp")
    set(BLUEWING_PLATFORM_SOURCES
        Lacewing/src/openssl/sslclient.c
        Lacewing/src/unix/client.c
        Lacewing/src/unix/event.c
        Lacewing/src/unix/eventpump.c
        Lacewing/src/unix/fdstream.c
        Lacewing/src/unix/file.c
        Lacewing/src/unix/global2.c
        Lacewing/src/unix/server.c
        Lacewing/src/unix/sync.c
        Lacewing/src/unix/thread.c
        Lacewing/src/unix/timer.c
        Lacewing/src/unix/udp.c
    )

    check_include_files(malloc.h HAVE_MALLOC_H)
    check_include_files(netdb.h HAVE_NETDB_H)
    check_include_files(sys/prctl.h HAVE_SYS_PRCTL_H)
    check_include_files(sys/sendfile.h HAVE_SYS_SENDFILE_H)
    if(ANDROID AND CMAKE_SYSTEM_VERSION VERSION_LESS 19)
        set(HAVE_SYS_TIMERFD_H OFF)
    else()
        check_include_files(sys/timerfd.h HAVE_SYS_TIMERFD_H)
    endif()

    if(APPLE)
        check_include_files(malloc/malloc.h HAVE_MALLOC_MALLOC_H)
        list(APPEND BLUEWING_PLATFORM_DEFINITIONS __APPLE_USE_RFC_3542)
    endif()

    check_symbol_exists(PR_SET_NAME "sys/prctl.h" HAVE_DECL_PR_SET_NAME)
    check_symbol_exists(TCP_CORK "netinet/tcp.h" HAVE_DECL_TCP_CORK)
    check_symbol_exists(TCP_NOPUSH "netinet/tcp.h" HAVE_DECL_TCP_NOPUSH)
    check_symbol_exists(MSG_NOSIGNAL "sys/socket.h" HAVE_DECL_MSG_NOSIGNAL)
    check_symbol_exists(SO_NOSIGPIPE "sys/socket.h" HAVE_DECL_SO_NOSIGPIPE)

    check_function_exists(kqueue USE_KQUEUE)
    if(NOT USE_KQUEUE)
        check_function_exists(epoll_create USE_EPOLL)
    endif()

    if(USE_KQUEUE)
        list(APPEND BLUEWING_PLATFORM_SOURCES Lacewing/src/unix/eventqueue/kqueue.c)
    elseif(USE_EPOLL)
        list(APPEND BLUEWING_PLATFORM_SOURCES Lacewing/src/unix/eventqueue/epoll.c)
    else() # USE_SELECT
        list(APPEND BLUEWING_PLATFORM_SOURCES Lacewing/src/unix/eventqueue/select.c)
    endif()

    if(ENABLE_SSL)
        find_package(OpenSSL REQUIRED)
        list(APPEND BLUEWING_PLATFORM_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
    endif()

    if(ENABLE_THREADS)
        find_package(Threads REQUIRED)
        list(APPEND BLUEWING_PLATFORM_LIBRARIES Threads::Threads)
        if(CMAKE_USE_PTHREADS_INIT)
            list(APPEND BLUEWING_PLATFORM_DEFINITIONS HAVE_PTHREADS)
        endif()
    endif()
    list(APPEND BLUEWING_PLATFORM_LIBRARIES ${CMAKE_DL_LIBS})
    check_function_exists(timegm HAVE_TIMEGM)
else()
    message(FATAL_ERROR "Unknown platform (not Windows or UNIX?)")
endif()

foreach(definition
        HAVE_MALLOC_H
        HAVE_MALLOC_MALLOC_H
        HAVE_NETDB_H
        HAVE_SYS_PRCTL_H
        HAVE_SYS_SENDFILE_H
        HAVE_SYS_TIMERFD_H
        HAVE_DECL_PR_SET_NAME
        HAVE_DECL_TCP_CORK
        HAVE_DECL_TCP_NOPUSH
        HAVE_DECL_MSG_NOSIGNAL
        HAVE_DECL_SO_NOSIGPIPE
        HAVE_TIMEGM
        USE_KQUEUE
        USE_EPOLL)
    if(${definition})
        list(APPEND BLUEWING_PLATFORM_DEFINITIONS ${definition})
    endif()
endforeach()

add_executable(bluewing-cpp-server
    ${BLUEWING_CONSOLE_SOURCE}
    ${BLUEWING_COMMON_SOURCES}
    ${BLUEWING_PLATFORM_SOURCES}
)

set_target_properties(bluewing-cpp-server PROPERTIES
    OUTPUT_NAME "${BLUEWING_PROJECT_NAME}"
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS YES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

target_include_directories(bluewing-cpp-server PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/Lacewing"
)

target_compile_definitions(bluewing-cpp-server PRIVATE
    PROJECT_NAME=\"${BLUEWING_PROJECT_NAME}\"
    _lacewing_static
    ${BLUEWING_PLATFORM_DEFINITIONS}
    $<$<BOOL:${ENABLE_CXX}>:ENABLE_CXX>
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
)

if(WIN32)
    target_compile_definitions(bluewing-cpp-server PRIVATE
        _CRT_SECURE_NO_WARNINGS
        _WINSOCK_DEPRECATED_NO_WARNINGS
        _CONSOLE
        lw_import=
    )

    option(BLUEWING_ENABLE_WINDOWS_RESOURCES
        "Embed the Visual Studio project's Windows icon and manifest" ON)
    if(BLUEWING_ENABLE_WINDOWS_RESOURCES)
        enable_language(RC)
        target_sources(bluewing-cpp-server PRIVATE Resource.rc)
    endif()

    if(MSVC)
        target_link_options(bluewing-cpp-server PRIVATE
            /SUBSYSTEM:CONSOLE
            /DEBUG
            $<$<CONFIG:Release>:/OPT:REF>
            $<$<CONFIG:Release>:/OPT:ICF>
        )
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # Support a Clang Windows toolchain that is not clang-cl.
        target_link_options(bluewing-cpp-server PRIVATE
            -Wl,--subsystem,console
            $<$<CONFIG:Release>:-Wl,--gc-sections>
        )
    endif()

    if(MSVC AND BLUEWING_ENABLE_WINDOWS_RESOURCES)
        target_link_options(bluewing-cpp-server PRIVATE
            "/MANIFESTINPUT:${CMAKE_CURRENT_SOURCE_DIR}/manifest.xml"
        )
    endif()
endif()

if(UNIX AND ENABLE_SSL)
    target_compile_definitions(bluewing-cpp-server PRIVATE ENABLE_SSL)
endif()

if(UNIX AND ENABLE_THREADS)
    target_compile_definitions(bluewing-cpp-server PRIVATE ENABLE_THREADS)
endif()

target_link_libraries(bluewing-cpp-server PRIVATE ${BLUEWING_PLATFORM_LIBRARIES})

# Linux and Android both use ELF linkers; Apple platforms use Mach-O and do
# not accept these GNU-style hardening options.
if((CMAKE_SYSTEM_NAME STREQUAL "Linux" OR ANDROID)
   AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(bluewing-cpp-server PRIVATE
        -Wl,-z,relro
        -Wl,-z,noexecstack
        -Wl,--no-undefined
        -Wl,-z,now
    )
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    target_compile_options(bluewing-cpp-server PRIVATE
        $<$<COMPILE_LANGUAGE:C>:-Wno-deprecated-declarations>
    )
endif()

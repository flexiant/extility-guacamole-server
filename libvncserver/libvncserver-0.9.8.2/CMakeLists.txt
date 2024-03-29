cmake_minimum_required(VERSION 2.6)

project(LibVNCServer)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckTypeSize)
include(TestBigEndian)

set(PACKAGE_NAME           "LibVNCServer")
set(FULL_PACKAGE_NAME      "LibVNCServer")
set(PACKAGE_VERSION        "0.9.8.2")
set(PROJECT_BUGREPORT_PATH "http://sourceforge.net/projects/libvncserver")

include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/libvncserver ${CMAKE_SOURCE_DIR}/common)

find_package(ZLIB)
find_package(JPEG)
find_package(SDL)
find_package(GnuTLS)
find_package(Threads)
find_package(X11)
find_library(LIBGCRYPT_LIBRARIES gcrypt)

if(Threads_FOUND)
  option(TIGHTVNC_FILETRANSFER "Enable filetransfer" ON)
endif(Threads_FOUND)
if(ZLIB_FOUND)
  set(LIBVNCSERVER_HAVE_LIBZ 1)
endif(ZLIB_FOUND)
if(JPEG_FOUND)
  set(LIBVNCSERVER_HAVE_LIBJPEG 1)
endif(JPEG_FOUND)
option(LIBVNCSERVER_ALLOW24BPP "Allow 24 bpp" ON)
if(GNUTLS_FOUND)
  set(LIBVNCSERVER_WITH_CLIENT_TLS 1)
endif(GNUTLS_FOUND)
if(LIBGCRYPT_LIBRARIES)
  message(STATUS "Found libgcrypt: ${LIBGCRYPT_LIBRARIES}")
  set(LIBVNCSERVER_WITH_CLIENT_GCRYPT 1)
endif(LIBGCRYPT_LIBRARIES)


check_include_file("fcntl.h"       LIBVNCSERVER_HAVE_FCNTL_H)
check_include_file("netinet/in.h"  LIBVNCSERVER_HAVE_NETINET_IN_H)
check_include_file("sys/socket.h"  LIBVNCSERVER_HAVE_SYS_SOCKET_H)
check_include_file("sys/stat.h"    LIBVNCSERVER_HAVE_SYS_STAT_H)
check_include_file("sys/time.h"    LIBVNCSERVER_HAVE_SYS_TIME_H)
check_include_file("sys/types.h"   LIBVNCSERVER_HAVE_SYS_TYPES_H)
check_include_file("sys/wait.h"    LIBVNCSERVER_HAVE_SYS_WAIT_H)
check_include_file("unistd.h"      LIBVNCSERVER_HAVE_UNISTD_H)

# headers needed for check_type_size()
check_include_file("arpa/inet.h"   HAVE_ARPA_INET_H)
check_include_file("stdint.h"      HAVE_STDINT_H)
check_include_file("stddef.h"      HAVE_STDDEF_H)
check_include_file("sys/types.h"   HAVE_SYS_TYPES_H)

check_function_exists(gettimeofday    LIBVNCSERVER_HAVE_GETTIMEOFDAY)

if(CMAKE_USE_PTHREADS_INIT)
  set(LIBVNCSERVER_HAVE_LIBPTHREAD 1)
endif(CMAKE_USE_PTHREADS_INIT)
if(LIBVNCSERVER_HAVE_SYS_SOCKET_H)
  # socklen_t
  list(APPEND CMAKE_EXTRA_INCLUDE_FILES "sys/socket.h")
endif(LIBVNCSERVER_HAVE_SYS_SOCKET_H)
if(HAVE_ARPA_INET_H)
  # in_addr_t
  list(APPEND CMAKE_EXTRA_INCLUDE_FILES "arpa/inet.h")
endif(HAVE_ARPA_INET_H)

check_type_size(pid_t     LIBVNCSERVER_PID_T)
check_type_size(size_t    LIBVNCSERVER_SIZE_T)
check_type_size(socklen_t LIBVNCSERVER_SOCKLEN_T)
check_type_size(in_addr_t LIBVNCSERVER_IN_ADDR_T)
if(NOT HAVE_LIBVNCSERVER_IN_ADDR_T)
  set(LIBVNCSERVER_NEED_INADDR_T 1)
endif(NOT HAVE_LIBVNCSERVER_IN_ADDR_T)

TEST_BIG_ENDIAN(LIBVNCSERVER_WORDS_BIGENDIAN)

# TODO:
# LIBVNCSERVER_ENOENT_WORKAROUND
# inline

configure_file(${CMAKE_SOURCE_DIR}/rfb/rfbconfig.h.cmake ${CMAKE_BINARY_DIR}/rfb/rfbconfig.h)
configure_file(${CMAKE_SOURCE_DIR}/rfb/rfbint.h.cmake ${CMAKE_BINARY_DIR}/rfb/rfbint.h)

set(LIBVNCSERVER_DIR ${CMAKE_SOURCE_DIR}/libvncserver)
set(COMMON_DIR ${CMAKE_SOURCE_DIR}/common)
set(LIBVNCCLIENT_DIR ${CMAKE_SOURCE_DIR}/libvncclient)
set(LIBVNCSRVTEST_DIR ${CMAKE_SOURCE_DIR}/examples)
set(LIBVNCCLITEST_DIR ${CMAKE_SOURCE_DIR}/client_examples)

set(LIBVNCSERVER_SOURCES
    ${LIBVNCSERVER_DIR}/main.c
    ${LIBVNCSERVER_DIR}/rfbserver.c
    ${LIBVNCSERVER_DIR}/rfbregion.c
    ${LIBVNCSERVER_DIR}/auth.c
    ${LIBVNCSERVER_DIR}/sockets.c
    ${LIBVNCSERVER_DIR}/stats.c
    ${LIBVNCSERVER_DIR}/corre.c
    ${LIBVNCSERVER_DIR}/hextile.c
    ${LIBVNCSERVER_DIR}/rre.c
    ${LIBVNCSERVER_DIR}/translate.c
    ${LIBVNCSERVER_DIR}/cutpaste.c
    ${LIBVNCSERVER_DIR}/httpd.c
    ${LIBVNCSERVER_DIR}/cursor.c
    ${LIBVNCSERVER_DIR}/font.c
    ${LIBVNCSERVER_DIR}/draw.c
    ${LIBVNCSERVER_DIR}/selbox.c
    ${COMMON_DIR}/d3des.c
    ${COMMON_DIR}/vncauth.c
    ${LIBVNCSERVER_DIR}/cargs.c
    ${COMMON_DIR}/minilzo.c
    ${LIBVNCSERVER_DIR}/ultra.c
    ${LIBVNCSERVER_DIR}/scale.c
)

set(LIBVNCCLIENT_SOURCES
    ${LIBVNCCLIENT_DIR}/cursor.c
    ${LIBVNCCLIENT_DIR}/listen.c
    ${LIBVNCCLIENT_DIR}/rfbproto.c
    ${LIBVNCCLIENT_DIR}/sockets.c
    ${LIBVNCCLIENT_DIR}/vncviewer.c
    ${COMMON_DIR}/minilzo.c
    ${LIBVNCCLIENT_DIR}/tls.c
)

if(ZLIB_FOUND)
  add_definitions(-DLIBVNCSERVER_HAVE_LIBZ)
  include_directories(${ZLIB_INCLUDE_DIR})
  set(LIBVNCSERVER_SOURCES
    ${LIBVNCSERVER_SOURCES}
    ${LIBVNCSERVER_DIR}/zlib.c
    ${LIBVNCSERVER_DIR}/zrle.c
    ${LIBVNCSERVER_DIR}/zrleoutstream.c
    ${LIBVNCSERVER_DIR}/zrlepalettehelper.c
  )
endif(ZLIB_FOUND)

if(JPEG_FOUND)
  add_definitions(-DLIBVNCSERVER_HAVE_LIBJPEG)
  include_directories(${JPEG_INCLUDE_DIR})
  set(LIBVNCSERVER_SOURCES
    ${LIBVNCSERVER_SOURCES}
    ${LIBVNCSERVER_DIR}/tight.c
  )
endif(JPEG_FOUND)

if(TIGHTVNC_FILETRANSFER)
  set(LIBVNCSERVER_SOURCES
    ${LIBVNCSERVER_SOURCES}
    ${LIBVNCSERVER_DIR}/tightvnc-filetransfer/rfbtightserver.c
    ${LIBVNCSERVER_DIR}/tightvnc-filetransfer/handlefiletransferrequest.c
    ${LIBVNCSERVER_DIR}/tightvnc-filetransfer/filetransfermsg.c
    ${LIBVNCSERVER_DIR}/tightvnc-filetransfer/filelistinfo.c
  )
endif(TIGHTVNC_FILETRANSFER)

add_library(vncclient SHARED ${LIBVNCCLIENT_SOURCES})
add_library(vncserver SHARED ${LIBVNCSERVER_SOURCES})
if(WIN32)
  set(ADDITIONAL_LIBS ws2_32)
endif(WIN32)

target_link_libraries(vncclient
                      ${ADDITIONAL_LIBS}
                      ${ZLIB_LIBRARIES}
                      ${JPEG_LIBRARIES}
                      ${SDL_LIBRARY}
)
target_link_libraries(vncserver
                      ${ADDITIONAL_LIBS}
                      ${ZLIB_LIBRARIES}
                      ${JPEG_LIBRARIES}
                      ${SDL_LIBRARY}
)

# tests
set(LIBVNCSERVER_TESTS
    backchannel
    camera
    colourmaptest
    example
    fontsel
    pnmshow
    pnmshow24
    regiontest
    rotate
    simple
    simple15
    storepasswd
    vncev
  )

if(Threads_FOUND)
  set(LIBVNCSERVER_TESTS
    ${LIBVNCSERVER_TESTS}
    blooptest
  )
endif(Threads_FOUND)

if(TIGHTVNC_FILETRANSFER)
  set(LIBVNCSERVER_TESTS
    ${LIBVNCSERVER_TESTS}
    filetransfer
  )
endif(TIGHTVNC_FILETRANSFER)

if(MACOS)
  set(LIBVNCSERVER_TESTS
    ${LIBVNCSERVER_TESTS}
    mac
  )
endif(MACOS)

set(LIBVNCCLIENT_TESTS
    backchannel
    ppmtest
)

if(SDL_FOUND)
  include_directories(${SDL_INCLUDE_DIR})
  set(LIBVNCCLIENT_TESTS
    ${LIBVNCCLIENT_TESTS}
    SDLvncviewer
  )
  set(SDLvncviewer_EXTRA_SOURCES scrap.c)
endif(SDL_FOUND)

if(HAVE_FFMPEG)
  set(LIBVNCCLIENT_TESTS
    ${LIBVNCCLIENT_TESTS}
    vnc2mpg
  )
endif(HAVE_FFMPEG)


file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/examples)
foreach(test ${LIBVNCSERVER_TESTS})
  add_executable(examples/${test} ${LIBVNCSRVTEST_DIR}/${test}.c)
  target_link_libraries(examples/${test} vncserver ${CMAKE_THREAD_LIBS_INIT})
endforeach(test ${LIBVNCSERVER_TESTS})

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/client_examples)
foreach(test ${LIBVNCCLIENT_TESTS})
  add_executable(client_examples/${test} ${LIBVNCCLITEST_DIR}/${test}.c ${LIBVNCCLITEST_DIR}/${${test}_EXTRA_SOURCES} )
  target_link_libraries(client_examples/${test} vncclient ${CMAKE_THREAD_LIBS_INIT} ${GNUTLS_LIBRARIES} ${X11_LIBRARIES} ${SDL_LIBRARY} ${FFMPEG_LIBRARIES})
endforeach(test ${LIBVNCCLIENT_TESTS})

install_targets(/lib vncserver)
install_targets(/lib vncclient)
install_files(/include/rfb FILES
    rfb/keysym.h
    rfb/rfb.h
    rfb/rfbclient.h
    rfb/rfbconfig.h
    rfb/rfbint.h
    rfb/rfbproto.h
    rfb/rfbregion.h
)

INCLUDES = -I$(top_srcdir)

CONSOLE_SRCS=VNConsole.c

noinst_HEADERS=VNConsole.h vga.h

LDADD=../libvncserver/libvncserver.la @WSOCKLIB@

if LINUX
if ! MINGW
bin_PROGRAMS=linuxvnc
linuxvnc_SOURCES=LinuxVNC.c $(CONSOLE_SRCS)
endif
endif

if ! MINGW
VNCOMMAND=VNCommand
endif

noinst_PROGRAMS=example $(VNCOMMAND)
example_SOURCES=example.c $(CONSOLE_SRCS)
VNCommand_SOURCES=VNCommand.c $(CONSOLE_SRCS)




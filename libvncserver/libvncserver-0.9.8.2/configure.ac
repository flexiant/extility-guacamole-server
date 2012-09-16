# Process this file with autoconf to produce a configure script.
AC_INIT(LibVNCServer, 0.9.8.2, http://sourceforge.net/projects/libvncserver)
AM_INIT_AUTOMAKE(LibVNCServer, 0.9.8.2)
AM_CONFIG_HEADER(rfbconfig.h)
AX_PREFIX_CONFIG_H([rfb/rfbconfig.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
if test -z "$CC"; then
	CCLD="\$(CC)"
else
	CCLD="$CC"
fi
test "x$GCC" = "xyes" && CFLAGS="$CFLAGS -Wall"
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_PATH_PROG([AR], [ar], [/usr/bin/ar],
                  [$PATH:/usr/ccs/bin])

# Options
AH_TEMPLATE(WITH_TIGHTVNC_FILETRANSFER, [Disable TightVNCFileTransfer protocol])
AC_ARG_WITH(tightvnc-filetransfer,
	[  --without-filetransfer  disable TightVNC file transfer protocol],
	, [ with_tightvnc_filetransfer=yes ])
# AC_DEFINE moved to after libpthread check.

AH_TEMPLATE(ALLOW24BPP, [Enable 24 bit per pixel in native framebuffer])
AC_ARG_WITH(24bpp,
	[  --without-24bpp         disable 24 bpp framebuffers],
	, [ with_24bpp=yes ])
if test "x$with_24bpp" = "xyes"; then
	AC_DEFINE(ALLOW24BPP)
fi
AH_TEMPLATE(FFMPEG, [Use ffmpeg (for vnc2mpg)])
AC_ARG_WITH(ffmpeg,
	[  --with-ffmpeg=dir       set ffmpeg home directory],,)
AC_SUBST(with_ffmpeg)
AM_CONDITIONAL(WITH_FFMPEG, test ! -z "$with_ffmpeg")
if test ! -z "$with_ffmpeg"; then
	AC_CHECK_LIB(mp3lame, lame_init, HAVE_MP3LAME="true", HAVE_MP3LAME="false" )
fi
AM_CONDITIONAL(HAVE_MP3LAME, test "$HAVE_MP3LAME" = "true")

# Seem to need this dummy here to induce the 'checking for egrep... grep -E', etc.
# before it seemed to be inside the with_jpeg conditional. 
AC_CHECK_HEADER(thenonexistentheader.h, HAVE_THENONEXISTENTHEADER_H="true")

# Checks for X libraries
HAVE_X11="false"
AC_PATH_XTRA
AH_TEMPLATE(HAVE_X11, [X11 build environment present])

# See if we are to build x11vnc:
AH_TEMPLATE(HAVE_SYSTEM_LIBVNCSERVER, [Use the system libvncserver build environment for x11vnc.])
AC_ARG_WITH(system-libvncserver,
[  --with-system-libvncserver     use installed libvncserver for x11vnc]
[  --with-system-libvncserver=DIR use libvncserver installed in DIR for x11vnc],,)
AC_ARG_WITH(x11vnc,
[  --with-x11vnc           configure for building the x11vnc subdir (if present)]
[                          you will need to cd to x11vnc and run 'make' etc.],,)

if test ! -z "$with_x11vnc" -a "$with_x11vnc" = "yes"; then
	build_x11vnc="yes"
elif test "$PACKAGE_NAME" = "x11vnc"; then
	build_x11vnc="yes"
else
	build_x11vnc="no"
fi
	
if test "x$with_x" = "xno"; then
	HAVE_X11="false"
elif test "$X_CFLAGS" != "-DX_DISPLAY_MISSING"; then
	AC_CHECK_LIB(X11, XGetImage, [AC_DEFINE(HAVE_X11) HAVE_X11="true"],
		HAVE_X11="false",
		$X_LIBS $X_PRELIBS -lX11 $X_EXTRA_LIBS)
fi

AC_SUBST(X_LIBS)
AM_CONDITIONAL(HAVE_X11, test $HAVE_X11 != "false")

# only used in x11vnc/Makefile.am but needs to always be defined:
AM_CONDITIONAL(OSX_OPENGL, test "$HAVE_MACOSX_OPENGL_H" = "true")

# Checks for libraries.

if test ! -z "$with_system_libvncserver" -a "x$with_system_libvncserver" != "xno"; then
	printf "checking for system libvncserver... "
	vneed="0.9.1"
	if test "X$VNEED" != "X"; then
		vneed=$VNEED
	fi
	if test "x$with_system_libvncserver" != "xyes"; then
		rflag=""
		if test "x$ld_minus_R" = "xno"; then
			:
		elif test "x$GCC" = "xyes"; then
			rflag="-Xlinker -R$with_system_libvncserver/lib"
		else
			rflag="-R$with_system_libvncserver/lib"
		fi
		cmd="$with_system_libvncserver/bin/libvncserver-config"
		if $cmd --version 1>/dev/null 2>&1; then
			cvers=`$cmd --version 2>/dev/null`
			cscore=`echo "$cvers" | tr '.' ' ' | awk '{print 10000 * $1 + 100 * $2 + $3}'`
			nscore=`echo "$vneed" | tr '.' ' ' | awk '{print 10000 * $1 + 100 * $2 + $3}'`

			if test $cscore -lt $nscore; then
				echo "no"
				with_system_libvncserver=no
				AC_MSG_ERROR([
==========================================================================
*** Need libvncserver version $vneed, have version $cvers ***
You are building with a system installed libvncserver and it is not
new enough.
==========================================================================
])
			else
				SYSTEM_LIBVNCSERVER_CFLAGS="-I$with_system_libvncserver/include"
				SYSTEM_LIBVNCSERVER_LIBS="-L$with_system_libvncserver/lib $rflag -lvncserver -lvncclient"
				echo "using $with_system_libvncserver"
				with_system_libvncserver=yes
			fi
		else
			echo " *** cannot run $cmd *** " 1>&2
			with_system_libvncserver=no
			echo no
		fi
	elif libvncserver-config --version 1>/dev/null 2>&1; then
		rflag=""
		rprefix=`libvncserver-config --prefix`
		if test "x$ld_minus_R" = "xno"; then
			:
		elif test "x$GCC" = "xyes"; then
			rflag=" -Xlinker -R$rprefix/lib "
		else
			rflag=" -R$rprefix/lib "
		fi
		cvers=`libvncserver-config --version 2>/dev/null`
		cscore=`echo "$cvers" | tr '.' ' ' | awk '{print 10000 * $1 + 100 * $2 + $3}'`
		nscore=`echo "$vneed" | tr '.' ' ' | awk '{print 10000 * $1 + 100 * $2 + $3}'`

		if test $cscore -lt $nscore; then
			echo "no"
				AC_MSG_ERROR([
==========================================================================
*** Need libvncserver version $vneed, have version $cvers ***
You are building with a system installed libvncserver and it is not
new enough.
==========================================================================
])
		else
			SYSTEM_LIBVNCSERVER_CFLAGS=`libvncserver-config --cflags`
			SYSTEM_LIBVNCSERVER_LIBS="$rflag"`libvncserver-config --libs`
			with_system_libvncserver=yes
			echo yes
		fi
	else
		with_system_libvncserver=no
		echo no
	fi
fi

if test "x$with_system_libvncserver" = "xyes"; then
	AC_DEFINE(HAVE_SYSTEM_LIBVNCSERVER)
	AC_SUBST(SYSTEM_LIBVNCSERVER_CFLAGS)
	AC_SUBST(SYSTEM_LIBVNCSERVER_LIBS)
fi
AM_CONDITIONAL(HAVE_SYSTEM_LIBVNCSERVER, test "x$with_system_libvncserver" = "xyes")


AC_ARG_WITH(jpeg,
[  --without-jpeg          disable support for jpeg]
[  --with-jpeg=DIR         use jpeg include/library files in DIR],,)

# At this point:
#	no jpeg on command line   with_jpeg=""
#	-with-jpeg                with_jpeg="yes"
#	-without-jpeg             with_jpeg="no"
#	-with-jpeg=/foo/dir       with_jpeg="/foo/dir"

if test "x$with_jpeg" != "xno"; then
	if test ! -z "$with_jpeg" -a "x$with_jpeg" != "xyes"; then
		# add user supplied directory to flags:
		saved_CPPFLAGS="$CPPFLAGS"
		saved_LDFLAGS="$LDFLAGS"
		CPPFLAGS="$CPPFLAGS -I$with_jpeg/include"
		LDFLAGS="$LDFLAGS -L$with_jpeg/lib"
		if test "x$ld_minus_R" = "xno"; then
			:
		elif test "x$GCC" = "xyes"; then
			# this is not complete... in general a rat's nest.
			LDFLAGS="$LDFLAGS -Xlinker -R$with_jpeg/lib"
		else
			LDFLAGS="$LDFLAGS -R$with_jpeg/lib"
		fi
	fi
	AC_CHECK_HEADER(jpeglib.h, HAVE_JPEGLIB_H="true")
	if test "x$HAVE_JPEGLIB_H" = "xtrue"; then
		AC_CHECK_LIB(jpeg, jpeg_CreateCompress, , HAVE_JPEGLIB_H="")
	fi
	if test ! -z "$with_jpeg" -a "x$with_jpeg" != "xyes"; then
		if test "x$HAVE_JPEGLIB_H" != "xtrue"; then
			# restore old flags on failure:
			CPPFLAGS="$saved_CPPFLAGS"
			LDFLAGS="$saved_LDFLAGS"
		fi
	fi
	if test "$build_x11vnc" = "yes"; then
		if test "x$HAVE_JPEGLIB_H" != "xtrue"; then
			AC_MSG_WARN([
==========================================================================
*** The libjpeg compression library was not found. ***
This may lead to reduced performance, especially over slow links.
If libjpeg is in a non-standard location use --with-jpeg=DIR to
indicate the header file is in DIR/include/jpeglib.h and the library
in DIR/lib/libjpeg.a.  A copy of libjpeg may be obtained from:
ftp://ftp.uu.net/graphics/jpeg/
==========================================================================
])
			sleep 5
		fi
	fi
fi

AC_ARG_WITH(libz,
[  --without-libz          disable support for deflate],,)
AC_ARG_WITH(zlib,
[  --without-zlib          disable support for deflate]
[  --with-zlib=DIR         use zlib include/library files in DIR],,)

if test "x$with_zlib" != "xno" -a "x$with_libz" != "xno"; then
	if test ! -z "$with_zlib" -a "x$with_zlib" != "xyes"; then
		saved_CPPFLAGS="$CPPFLAGS"
		saved_LDFLAGS="$LDFLAGS"
		CPPFLAGS="$CPPFLAGS -I$with_zlib/include"
		LDFLAGS="$LDFLAGS -L$with_zlib/lib"
		if test "x$ld_minus_R" = "xno"; then
			:
		elif test "x$GCC" = "xyes"; then
			LDFLAGS="$LDFLAGS -Xlinker -R$with_zlib/lib"
		else
			LDFLAGS="$LDFLAGS -R$with_zlib/lib"
		fi
	fi
	AC_CHECK_HEADER(zlib.h, HAVE_ZLIB_H="true")
	if test "x$HAVE_ZLIB_H" = "xtrue"; then
		AC_CHECK_LIB(z, deflate, , HAVE_ZLIB_H="")
	fi
	if test ! -z "$with_zlib" -a "x$with_zlib" != "xyes"; then
		if test "x$HAVE_ZLIB_H" != "xtrue"; then
			CPPFLAGS="$saved_CPPFLAGS"
			LDFLAGS="$saved_LDFLAGS"
		fi
	fi
	if test "$build_x11vnc" = "yes"; then
		if test "x$HAVE_ZLIB_H" != "xtrue"; then
			AC_MSG_WARN([
==========================================================================
*** The libz compression library was not found. ***
This may lead to reduced performance, especially over slow links.
If libz is in a non-standard location use --with-zlib=DIR to indicate the
header file is in DIR/include/zlib.h and the library in DIR/lib/libz.a.
A copy of libz may be obtained from: http://www.gzip.org/zlib/
==========================================================================
])
			sleep 5
		fi
	fi
fi

AC_ARG_WITH(pthread,
[  --without-pthread       disable support for libpthread],,)

if test "x$with_pthread" != "xno"; then
	AC_CHECK_HEADER(pthread.h, HAVE_PTHREAD_H="true")
	if test ! -z "$HAVE_PTHREAD_H"; then
		AC_CHECK_LIB(pthread, pthread_mutex_lock)
		AC_CHECK_LIB(pthread, pthread_mutex_lock, HAVE_LIBPTHREAD="true")
	fi
fi
AM_CONDITIONAL(HAVE_LIBPTHREAD, test ! -z "$HAVE_LIBPTHREAD")

AC_MSG_CHECKING([for __thread])
AC_LINK_IFELSE([AC_LANG_PROGRAM(, [static __thread int p = 0])],
	       [AC_DEFINE(HAVE_TLS, 1,
		      Define to 1 if compiler supports __thread)
		AC_MSG_RESULT([yes])],
	       [AC_MSG_RESULT([no])])

# tightvnc-filetransfer implemented using threads:
if test -z "$HAVE_LIBPTHREAD"; then
	with_tightvnc_filetransfer=""
fi
if test "x$with_tightvnc_filetransfer" = "xyes"; then
	AC_DEFINE(WITH_TIGHTVNC_FILETRANSFER)
fi
AM_CONDITIONAL(WITH_TIGHTVNC_FILETRANSFER, test "$with_tightvnc_filetransfer" = "yes")

AM_CONDITIONAL(HAVE_LIBZ, test ! -z "$HAVE_ZLIB_H")
AM_CONDITIONAL(HAVE_LIBJPEG, test ! -z "$HAVE_JPEGLIB_H")


SDLCONFIG="sdl-config"
AC_ARG_WITH(sdl-config,
[[  --with-sdl-config=FILE
    Use the given path to sdl-config when determining
    SDL configuration; defaults to "sdl-config"]],
[
    if test "$withval" != "yes" -a "$withval" != ""; then
        SDLCONFIG=$withval
    fi
])

if test -z "$with_sdl"; then
	if $SDLCONFIG --version >/dev/null 2>&1; then
		with_sdl=yes
		SDL_CFLAGS=`$SDLCONFIG --cflags`
		SDL_LIBS=`$SDLCONFIG --libs`
	else
		with_sdl=no
	fi
fi
AM_CONDITIONAL(HAVE_LIBSDL, test "x$with_sdl" = "xyes")
AC_SUBST(SDL_CFLAGS)
AC_SUBST(SDL_LIBS)


AC_CANONICAL_HOST
MINGW=`echo $host_os | grep mingw32  2>/dev/null`
AM_CONDITIONAL(MINGW, test ! -z "$MINGW" )
if test ! -z "$MINGW"; then
	WSOCKLIB="-lws2_32"
fi
AC_SUBST(WSOCKLIB)

# Check for libgcrypt
AH_TEMPLATE(WITH_CLIENT_GCRYPT, [Enable support for libgcrypt in libvncclient])
AC_ARG_WITH(gcrypt,
[  --without-gcrypt        disable support for gcrypt],,)
AC_ARG_WITH(client-gcrypt,
[  --without-client-gcrypt disable support for gcrypt in libvncclient],,)

if test "x$with_gcrypt" != "xno"; then
	AM_PATH_LIBGCRYPT(1.4.0, , with_client_gcrypt=no)
	CFLAGS="$CFLAGS $LIBGCRYPT_CFLAGS"
	LIBS="$LIBS $LIBGCRYPT_LIBS"
	if test "x$with_client_gcrypt" != "xno"; then
		AC_DEFINE(WITH_CLIENT_GCRYPT)
	fi
fi

# Checks for GnuTLS
AH_TEMPLATE(WITH_CLIENT_TLS, [Enable support for gnutls in libvncclient])
AC_ARG_WITH(gnutls,
[  --without-gnutls        disable support for gnutls],,)
AC_ARG_WITH(client-tls,
[  --without-client-tls    disable support for gnutls in libvncclient],,)

if test "x$with_gnutls" != "xno"; then
	PKG_CHECK_MODULES(GNUTLS, gnutls >= 2.4.0, , with_client_tls=no)
	CFLAGS="$CFLAGS $GNUTLS_CFLAGS"
	LIBS="$LIBS $GNUTLS_LIBS"
	if test "x$with_client_tls" != "xno"; then
		AC_DEFINE(WITH_CLIENT_TLS)
	fi
fi

# IPv6
AH_TEMPLATE(IPv6, [Enable IPv6 support])
AC_ARG_WITH(ipv6,
[  --without-ipv6          disable IPv6 support],,)
if test "x$with_ipv6" != "xno"; then
	AC_CHECK_FUNC(getaddrinfo, AC_DEFINE(IPv6,1),
		AC_CHECK_LIB(socket, getaddrinfo, AC_DEFINE(IPv6,1), [
			AC_MSG_CHECKING([for getaddrinfo in -lws2_32])
		        LIBS="$LIBS -lws2_32"
		        AC_TRY_LINK([#include <ws2tcpip.h>], [getaddrinfo(0, 0, 0, 0);], [
				      AC_DEFINE(IPv6,1)
		                      AC_MSG_RESULT([yes])
				      ],
				    AC_MSG_RESULT([no]))
                   ]))
fi



# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h sys/timeb.h syslog.h unistd.h ws2tcpip.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_C_BIGENDIAN
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_HEADER_SYS_WAIT
AC_TYPE_SOCKLEN_T
if test ! -d ./rfb; then
	echo "creating subdir ./rfb for rfbint.h"
	mkdir ./rfb 
fi
AC_CREATE_STDINT_H(rfb/rfbint.h)
AC_CACHE_CHECK([for in_addr_t],
        vnc_cv_inaddrt, [
                AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>],
                        [in_addr_t foo; return 0;],
                                        [inaddrt=yes],
                                        [inaddrt=no]),
        ])
AH_TEMPLATE(NEED_INADDR_T, [Need a typedef for in_addr_t])
if test $inaddrt = no ; then
  AC_DEFINE(NEED_INADDR_T)
fi

# Checks for library functions.
AC_FUNC_MEMCMP
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_FUNC_FORK
AC_CHECK_LIB(nsl,gethostbyname)
AC_CHECK_LIB(socket,socket)

uname_s=`(uname -s) 2>/dev/null`
if test "x$uname_s" = "xHP-UX"; then
	# need -lsec for getspnam()
	LDFLAGS="$LDFLAGS -lsec"
fi

AC_CHECK_FUNCS([ftime gethostbyname gethostname gettimeofday inet_ntoa memmove memset mmap mkfifo select socket strchr strcspn strdup strerror strstr])

# check, if shmget is in cygipc.a
AC_CHECK_LIB(cygipc,shmget)
AM_CONDITIONAL(CYGIPC, test "$HAVE_CYGIPC" = "true")

# Check if /usr/include/linux exists, if so, define LINUX
AM_CONDITIONAL(LINUX, test -d /usr/include/linux)

# Check for OS X specific header
AC_CHECK_HEADER(ApplicationServices/ApplicationServices.h, HAVE_OSX="true")
AM_CONDITIONAL(OSX, test "$HAVE_OSX" = "true")

# On Solaris 2.7, write() returns ENOENT when it really means EAGAIN
AH_TEMPLATE(ENOENT_WORKAROUND, [work around when write() returns ENOENT but does not mean it])
case `(uname -sr) 2>/dev/null` in
    "SunOS 5.7")
	AC_DEFINE(ENOENT_WORKAROUND)
    ;;
esac

# Check for rpm SOURCES path
printf "checking for rpm sources path... "
RPMSOURCEDIR="NOT-FOUND"
for directory in packages OpenLinux redhat RedHat rpm RPM "" ; do
	if test -d /usr/src/${directory}/SOURCES; then
		RPMSOURCEDIR="/usr/src/${directory}/SOURCES/"
	fi
done
echo "$RPMSOURCEDIR"
AM_CONDITIONAL(HAVE_RPM, test "$RPMSOURCEDIR" != "NOT-FOUND")
AM_CONDITIONAL(WITH_X11VNC,  test "$build_x11vnc" = "yes")
AC_SUBST(RPMSOURCEDIR)

AC_CONFIG_FILES([Makefile
	libvncserver.pc
	libvncclient.pc
	libvncserver/Makefile
	examples/Makefile
	vncterm/Makefile
	libvncclient/Makefile
	client_examples/Makefile
	test/Makefile
	libvncserver-config
	LibVNCServer.spec])

AC_CONFIG_COMMANDS([chmod-libvncserver-config],[chmod a+x libvncserver-config])
AC_OUTPUT
chmod a+x ./libvncserver-config


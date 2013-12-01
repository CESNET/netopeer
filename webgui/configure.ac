#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([netconfwebgui], [0.13.0], [tmc@cesnet.cz])
AM_INIT_AUTOMAKE([silent-rules tar-pax])

USERNAME=`git config --get user.name`
USERMAIL=`git config --get user.email`
AC_SUBST(USERNAME)
AC_SUBST(USERMAIL)

RELEASE=1
AC_SUBST(RELEASE)
LIBS="-lnetconf -ljson"

if test "x$webguidir" == x; then
	webguidir="/var/www"
fi
AC_ARG_VAR(webguidir, [Installation directory for webgui [/var/www]])
AC_SUBST(webguidir)

AC_ARG_VAR(httpdmoduledir, [Installation directory for Apache module, leave unset to use Apache default.])
AC_SUBST(httpdmoduledir)

if test "x$httpdconfddir" == x; then
	httpdconfddir="/etc/httpd/conf.d"
fi
AC_ARG_VAR(httpdconfddir, [Directory for Apache configuration files [/etc/httpd/conf.d]])
AC_SUBST(httpdconfddir)

if test "x$webguiname" == x; then
	webguiname="netconfwebgui"
fi
AC_ARG_VAR(webguiname, [Installation directory name for webgui [netconfwebgui]])
AC_SUBST(webguiname)

AC_ARG_ENABLE([composerinstall],
	AC_HELP_STRING([--disable-composerinstall], [disable PHP components installation. (used for distribution package)]),
[case "${enableval}" in
	yes) composerinstall=true ;;
	no)  composerinstall=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-composerinstall]) ;;
esac],[composerinstall=true])
AM_CONDITIONAL([SKIPCOMPOSER], [test x$composerinstall = xfalse])

AC_ARG_WITH(webgui, AC_HELP_STRING([--without-webgui],[Do not install WEBGUI frontend.]), [], [with_webgui="yes"])
AM_CONDITIONAL([WEBGUI_OPT], [test "x$with_webgui" != "xno"])

AC_ARG_WITH(modnetconf, AC_HELP_STRING([--without-modnetconf],[Do not compile and install mod_netconf.]), [], [with_modnetconf="yes"])
AM_CONDITIONAL([MODNETCONF_OPT], [test "x$with_modnetconf" != "xno"])

AC_ARG_WITH(pyang, AC_HELP_STRING([--without-pyang],[Do not install pyang plugins.]), [], [with_pyang="yes"])
AM_CONDITIONAL([PYANG_OPT], [test "x$with_pyang" != "xno"])

# Checks for programs.
AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],[name of the apxs executable [[apxs]]]), [APXS="$with_apxs"])
if test -z "${APXS}"; then
AC_PATH_PROGS(APXS, [apxs2 apxs], [no], [$PATH:/usr/sbin:/usr/local/apache2/bin])
else
AC_MSG_ERROR([Apxs for Apache module compilation and installation was not found.])
fi

# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, [rpmbuild], [rpmbuild], [""])
AC_CHECK_PROG(HTTPD, [httpd], [yes], [""])
AC_PATH_PROGS(APACHECTL, apachectl apache2ctl, no, [$PATH:/usr/sbin])

if test "x$APACHECTL" != xno; then
	AC_MSG_CHECKING([for php5_module in apache])
	$APACHECTL -M 2> /dev/null | grep php5_module > /dev/null && AC_MSG_RESULT([yes]) || AC_MSG_ERROR(["php5_module was not found."])
else
AC_MSG_ERROR([apachectl was not found])
fi

AC_PATH_PROGS(PHP, php, [no], [$PATH])
if test "x$PHP" != xno; then
	for i in dom json xml pdo intl sysvsem; do
		AC_MSG_CHECKING([for php module $i])
		php -m | grep "$i" > /dev/null && AC_MSG_RESULT([yes]) || AC_MSG_ERROR([not found])
	done
else
AC_MSG_ERROR([php was not found])
fi
AC_SUBST(PHP)

AC_CHECK_PROG(PYANG, [pyang], [yes], [""])
AC_PATH_PROGS(PYTHON, [python], [no], [$PATH])
if test "x$PYTHON" == xno; then
	AC_MSG_ERROR(["python was not found."])
fi

AC_ARG_VAR(pyplugindir, [Installation directory for pyang plugin])
if test "x$pyplugindir" == x; then
pyplugindir=[$(${PYTHON} -c 'from distutils.sysconfig import get_python_lib; print get_python_lib()+"/pyang/plugins"')]
fi
AC_SUBST(pyplugindir)

# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])
RPM_RELEASE=1
AC_SUBST(RPM_RELEASE)
AM_CONDITIONAL(MAKE_RPMS, test x$RPMBUILD != x)

# Checks for libraries.
# save clean LIBS and CFLAGS
SAVEDTEMP_LIBS=$LIBS
SAVEDTEMP_CFLAGS=$CFLAGS
#AC_CHECK_LIB([apr-1], [apr_hash_make])
#AC_CHECK_LIB([aprutil-1], [apr_sha1_init])
#AC_CHECK_LIB([netconf], [nc_session_connect])
#AC_CHECK_LIB([json], [json_object_new_object])
PKG_CHECK_MODULES([json], [json])
PKG_CHECK_MODULES([websockets], [libwebsockets])
PKG_CHECK_MODULES([apr], [apr-1])
PKG_CHECK_MODULES([aprutil], [apr-util-1])
PKG_CHECK_MODULES([netconf], [libnetconf])
PKG_CHECK_MODULES([xml], [libxml-2.0])
#$apr_CFLAGS $aprutil_CFLAGS 
#$apr_LIBS $aprutil_LIBS 
CFLAGS="$json_CFLAGS $websockets_CFLAGS $netconf_CFLAGS $xml_CFLAGS"
LIBS="$json_LIBS $websockets_LIBS $netconf_LIBS $xml_LIBS"
CPPFLAGS="$xml_CPPFLAGS"

AX_PTHREAD([LIBS="$PTHREAD_LIBS $LIBS"
	    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
	    CC="$PTHREAD_CC"],
	    [AC_MSG_ERROR([pthread not found])]
	   )
SAVED_LIBS=$LIBS
SAVED_CFLAGS=$CFLAGS

AC_SUBST(SAVED_LIBS)
AC_SUBST(SAVED_CFLAGS)

AC_ARG_WITH([notifications],
[AC_HELP_STRING([--without-notifications], [Disable notifications])],
AS_IF([test "x$with_notifications" == "xno"],[CFLAGS="$CFLAGS"],
[AC_CHECK_LIB([websockets], [libwebsocket_create_context])
CFLAGS="$CFLAGS -DWITH_NOTIFICATIONS"]),
[AC_CHECK_LIB([websockets], [libwebsocket_create_context])
CFLAGS="$CFLAGS -DWITH_NOTIFICATIONS"])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([getdelim gettimeofday memset socket strdup strerror])

AC_CONFIG_FILES([Makefile
		netconfwebgui.spec
		apache/src/Makefile
		symfony_gui/Makefile
		symfony_gui/netconfwebgui.conf
		pyang/Makefile])
AC_OUTPUT

echo
echo
echo "------------------------------------------------------------------------"
echo "$PACKAGE $VERSION"
echo "------------------------------------------------------------------------"
echo
echo
echo "Configuration Options Summary:"
echo
echo "Documentation..........: ${build_doc}"
echo
echo "Compilation............: make (or gmake)"
echo "  asxs.................: $ASXS"
echo "  LIBS.................: $LIBS"
echo "  CFLAGS...............: $CFLAGS"
echo
echo "Components"
echo "  mod_netconf..........: $with_modnetconf"
echo "  webgui frontend......: $with_webgui"
echo "  pyang plugins........: $with_pyang"
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo "  python module dir....: $pyplugindir"
echo "  webgui dir...........: $webguidir"
echo "  webgui name..........: $webguiname"
echo "  httpdmoduledir.......: $(test -z "$httpdmoduledir" && echo "Apache default path" || echo "$httpdmoduledir")"
echo "  httpdconfddir........: $(test -z "$httpdconfddir" && echo "Apache default path" || echo "$httpdconfddir")"
echo "  run composer install.: $composerinstall"
echo


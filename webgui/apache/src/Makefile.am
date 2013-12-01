SRCS=mod_netconf.c \
     notification-server.c

HDRS=message_type.h \
     notification_module.h \
     mod_netconf.h

noinst_PROGRAMS=webgui-backend test-client
webgui_backend_SOURCES=mod_netconf.c notification-server.c message_type.h notification_module.h mod_netconf.h
test_client_SOURCES=test-client.c

EXTRA_DIST=$(SRCS) $(HDRS)

dist-hook:
	cp $(SRC) $(HDRS) $(distdir)

all: mod_netconf.so test-client webgui-backend

mod_netconf.so: mod_netconf.c notification-server.c
	$(APXS) $(LIBS) $(CFLAGS) -c -o $@ $(srcdir)/mod_netconf.c $(srcdir)/notification-server.c

test-client$(EXEEXT): test-client.c
	gcc -std=gnu99 -Wall -g -ljson -I/usr/include/json -o $@ $<

#notification-test$(EXEEXT): notification-server.c
#	gcc -std=gnu99 -Wall -g -lwebsockets -DTEST_NOTIFICATION_SERVER -o $@ $<

install-exec-local: mod_netconf.so
	[ "x$(httpdmoduledir)" == x ] && \
	$(APXS) -i -a mod_netconf.la || \
	{ mkdir -p "$(httpdmoduledir)"; $(APXS) -i -S LIBEXECDIR="$(httpdmoduledir)" -a mod_netconf.la; }

webgui-backend$(EXEEXT): mod_netconf.c notification-server.c mod_netconf.h
	gcc -Wall -g $(LIBS) $(CFLAGS) -DHTTPD_INDEPENDENT  `apr-1-config  --cflags --cppflags --includes --link-ld` -I/usr/include/httpd  -laprutil-1 -o $@ $(srcdir)/mod_netconf.c $(srcdir)/notification-server.c

clean-local:
	rm -rf .libs *.la *.lo *.slo test-client webgui-backend

distclean-local:
	rm -rf $(RPMDIR)


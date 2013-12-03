ACLOCAL_AMFLAGS = -I m4

if MODNETCONF_OPT
  MODNETCONF_OPT=apache/src
else
  MODNETCONF_OPT=
endif
if PYANG_OPT
  PYANG_OPT=pyang
else
  PYANG_OPT=
endif
if WEBGUI_OPT
  WEBGUI_OPT=symfony_gui
else
  WEBGUI_OPT=
endif

SUBDIRS=$(WEBGUI_OPT) $(MODNETCONF_OPT) $(PYANG_OPT)

RPMDIR = RPMBUILD

dist-hook:
	find "$(distdir)" -name .gitignore -exec rm {} \;

if MAKE_RPMS

RPMFILENAME=$(PACKAGE_NAME)-$(VERSION)
.PHONY: rpm
rpm:
	rm -rf "$(RPMDIR)/SOURCES/$(RPMFILENAME)"
	mkdir -p $(RPMDIR)/BUILD/ $(RPMDIR)/SRPMS/ $(RPMDIR)/RPMS/ $(RPMDIR)/SOURCES
	make ${AM_MAKEFLAGS} distdir='$(RPMDIR)/SOURCES/$(RPMFILENAME)' distdir
	cp apache/src/mod_netconf.conf "$(RPMDIR)/SOURCES/$(RPMFILENAME)"
	find "$(RPMDIR)" -name '*.back' -exec rm -f {} \;
	( cd "$(RPMDIR)/SOURCES/"; tar -z -c -f $(RPMFILENAME)-$(RELEASE).tar.gz $(RPMFILENAME); rm -rf $(RPMFILENAME); )
	$(RPMBUILD) -ba $(PACKAGE_NAME).spec --define "_topdir `pwd`/$(RPMDIR)";

rpm-clean:
	rm -rf $(RPMDIR)
else
endif

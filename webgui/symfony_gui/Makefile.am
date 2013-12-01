EXTRA_DATA=www

dist-hook:
	cp -R www "$(distdir)"

if SKIPCOMPOSER
skipcomp=\# 
else
skipcomp=
endif

install-data-hook:
	[ -e "$(httpdconfddir)" ] || mkdir -p "$(httpdconfddir)"; \
	[ -e "$(httpdconfddir)/$(webguiname).conf" ] && mv "$(httpdconfddir)/$(webguiname).conf" "$(httpdconfddir)/$(webguiname).conf.back"; \
	cp netconfwebgui.conf $(httpdconfddir)/$(webguiname).conf;
	[ -e "$(webguidir)" ] || mkdir -p "$(webguidir)"; \
	[ -e "$(webguidir)/$(webguiname)" ] && cp -R www/* $(webguidir)/$(webguiname) || \
	cp -R www $(webguidir)/$(webguiname)
	$(skipcomp) cd $(webguidir)/$(webguiname) && $(PHP) composer.phar install;
	chmod a+x "$(webguidir)/$(webguiname)"/src/FIT/NetopeerBundle/bin/netconfwebgui-postinstall.sh
	cd "$(webguidir)/$(webguiname)/src/FIT/NetopeerBundle/"; \
	$(shell bin/netconfwebgui-postinstall.sh)

uninstall-hook:
	find "$(webguidir)/$(webguiname)" -type f -exec rm {} \;
	rm -f $(httpdconfddir)/$(webguiname).conf


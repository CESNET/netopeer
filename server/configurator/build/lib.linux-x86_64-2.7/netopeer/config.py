#!/usr/bin/python
# -*- coding:utf-8 -*-

import string

# all potentially useful paths
# ./configure creates config.py that is used in runtime

paths = {
		'prefix' : '/usr/local',\
		'exec_prefix' : '${prefix}',\
		'datarootdir' : '${prefix}/share',\
		'datadir' : '${datarootdir}',\
		'bindir' : '${exec_prefix}/bin',\
		'includedir' : '${prefix}/include',\
		'libdir' : '${prefix}/lib64',\
		'mandir' : '${datarootdir}/man',\
		'sysconfdir': '/',\
		'cfgdir': '//netopeer',\
		'crehash': '',\
		'dbusconfdir':'',\
		'dbusservices':'',\
		'modulesdir':'//netopeer/modules.conf.d/',\
	}

options = {
		'dbus' : True if string.find('-I/usr/local/include    -DDISABLE_DBUS -I/usr/include/libxml2', 'DISABLE_DBUS') < 0 else False,\
		'tls'  : True if string.find('-I/usr/local/include    -DDISABLE_DBUS -I/usr/include/libxml2', 'ENABLE_TLS') >= 0 else False,\
		'user' : 'root',\
		'group' : '',\
	}

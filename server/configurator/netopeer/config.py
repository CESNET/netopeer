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
		'sysconfdir': '${prefix}/etc',\
		'cfgdir': '${prefix}/etc/netopeer',\
		'modulesdir':'${prefix}/etc/netopeer/modules.conf.d/',\
	}

options = {
		'user' : 'root',\
		'ssh' : 'yes',\
		'tls' : 'no',\
	}

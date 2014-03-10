#!/usr/bin/python
# -*- coding:utf-8 -*-

import config

def consolidate_paths(paths):
	"""Consolidate paths."""
	# path starting and ending with '@' was not replaced, set to ''
	for path in paths:
		if paths[path] and paths[path][0] == '@' and paths[path][-1] == '@':
			paths[path] = ''

	# substitute all paths
	while True:
		changed = False
		for name,path in paths.iteritems():
			for pattern,new in paths.iteritems():
				if '${{{s}}}'.format(s=pattern) in path:
					changed = True
				path = path.replace('${{{s}}}'.format(s=pattern), new)
			paths[name] = path
		if not changed:
			break

# when inporting all import only configuring modules
__all__ = ['sshd', 'nacm', 'netopeer', 'dbus']
# consolidate configure paths
consolidate_paths(config.paths)

#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import ncmodule
import messages
import config

class nc_sock(ncmodule.ncmodule):
	name = 'Intercommunication'

	def find(self):
		return(True)

	def get(self):
		return(True)

	def update(self):
		return(True)

	def paint(self, window, focus, height, width):
		tools = []
		try:
			window.addstr('For intercommunication between Netopeer server and agents is used: UNIX sockets\n\n')

			window.addstr('To change the values below, recompile the Netopeer server\nwith the configure options --with-user and --with-group.\n\n')
			window.addstr('Allowed user to start the Netopeer server:\n')
			window.addstr('  {s}\n\n'.format(s=config.options['user']))

			if config.options['group'] == '':
				window.addstr('All users are allowed to connect to the Netopeer server.\n')
			else:
				window.addstr('Allowed group to connect to the Netopeer server:\n')
				window.addstr('  {s}\n\n'.format(s=config.options['group']))
		except curses.error:
			pass

		return(tools)

	def handle(self, stdscr, window, height, width, key):
		return(True)

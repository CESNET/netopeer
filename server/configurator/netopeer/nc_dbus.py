#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import libxml2
import re
import ncmodule
import messages
import config

class nc_dbus(ncmodule.ncmodule):
	name = 'Intercommunication'

	# permissions file path
	permission_path = None

	# dbus_permissions
	service_path = None
	service_content = None

	dbus_doc = None
	dbus_ctxt = None

	linewidth = 50

	user = None
	group = None

	#curses
	selected = 0

	def find(self):
		if len(config.paths['dbusconfdir']) and os.path.exists(os.path.join(config.paths['dbusconfdir'],'org.liberouter.netopeer.conf')):
			self.permission_path = os.path.join(config.paths['dbusconfdir'],'org.liberouter.netopeer.conf')
		else:
			messages.append('Netopeer DBus configuration file not found.', 'error')
			return(False)

		if len(config.paths['dbusservices']) and os.path.exists(os.path.join(config.paths['dbusservices'],'org.liberouter.netopeer.server.service')):
			self.service_path = os.path.join(config.paths['dbusservices'],'org.liberouter.netopeer.server.service')
		elif os.path.exists('/usr/share/dbus-1/system-services/org.liberouter.netopeer.server.service'):
			self.service_path = '/usr/share/dbus-1/system-services/org.liberouter.netopeer.server.service'
		else:
			messages.append('Netopeer DBus service autostart file not installed.', 'note')

		return(True)

	def get(self):
		if not self.permission_path:
			messages.append('Netopeer DBus configuration file location not specified.', 'error')
			return(False)

		try:
			self.dbus_doc = libxml2.parseFile(self.permission_path)
		except:
			messages.append('Unable to parse DBus configuration file', 'error')
			return(False)

		self.dbus_ctxt = self.dbus_doc.xpathNewContext()
		xpath_user = self.dbus_ctxt.xpathEval('/busconfig/policy[@user and allow/@own = \'org.liberouter.netopeer.server\']/@user')
		if xpath_user:
			self.user = xpath_user[0].get_content()
			if len(self.user) >= self.linewidth:
				self.linewidth = len(self.user) + 3

		xpath_group = self.dbus_ctxt.xpathEval('/busconfig/policy[@group and allow/@send_destination = \'org.liberouter.netopeer.server\' and allow/@receive_sender = \'org.liberouter.netopeer.server\']/@group')
		if xpath_group:
			self.group = xpath_group[0].get_content()
			if len(self.group) >= self.linewidth:
				self.linewidth = len(self.group) + 3

		if self.service_path:
			service = open(self.service_path, 'r')
			self.service_content = service.read()
			service.close()

		return(True)

	def update(self):
		if not self.permission_path:
			messages.append('Netopeer DBus configuration file location not specified.', 'error')
			return(False)

		xpath_user = self.dbus_ctxt.xpathEval('/busconfig/policy[@user and allow/@own = \'org.liberouter.netopeer.server\']/@user')
		if xpath_user:
			xpath_user[0].setContent(self.user)

		xpath_group = self.dbus_ctxt.xpathEval('/busconfig/policy[@group and allow/@send_destination = \'org.liberouter.netopeer.server\' and allow/@receive_sender = \'org.liberouter.netopeer.server\']/@group')
		if xpath_group:
			xpath_group[0].setContent(self.group)

		self.dbus_doc.saveFormatFile(self.permission_path, 1)

		if self.service_path:
			if self.service_content.find('User=') != -1:
				self.service_content = re.sub('User=.*$', 'User='+self.user, self.service_content)
			else:
				self.service_content = self.service_content + '\nUser=' + self.user

			service = open(self.service_path, 'w')
			service.write(self.service_content)
			service.close()

		return(True)

	def paint(self, window, focus, height, width):
		tools = []
		try:
			window.addstr('For intercommunication between Netopeer server and agents is used: DBus\n\n')

			window.addstr('Netopeer DBus configuration file:\n')
			window.addstr('{s}\n\n'.format(s=self.permission_path), curses.color_pair(0) | curses.A_UNDERLINE)
			if self.service_path:
				window.addstr('Netopeer DBus service autostart file:\n')
				window.addstr('{s}\n\n'.format(s=self.service_path), curses.color_pair(0) | curses.A_UNDERLINE)

			window.addstr('Allowed user to start the Netopeer server:\n')
			window.addstr('  {s}\n\n'.format(s=config.options['user']))

			if self.group == None:
				window.addstr('All users are allowed to connect to the Netopeer server.\n')
			else:
				window.addstr('Allowed group to connect to the Netopeer server:\n')
				msg = '  {s}'.format(s=self.group)
				window.addstr(msg+' '*(self.linewidth - len(msg)),curses.color_pair(0) | curses.A_REVERSE if (focus and self.selected == 0) else 0)
				window.addstr('\n\n')
		except curses.error:
			pass

		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < 0:
			self.selected = self.selected+1
		elif key == ord('\n'):
			if self.selected == 0 and self.group != None:
				try:
					window.addstr(12 if self.service_path else 9, 0, '> _'+' '*(self.linewidth-3),  curses.color_pair(0))
				except curses.error:
					pass
				self.group = self.get_editable(12 if self.service_path else 9, 2, stdscr, window, self.group, curses.color_pair(1) | curses.A_REVERSE)
				if len(self.group) >= self.linewidth:
					self.linewidth = len(self.group) + 3
			else:
				curses.flash()
		else:
			curses.flash()
		return(True)

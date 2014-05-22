#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import libxml2
import nc_module
import messages
import config

class dbus(nc_module.nc_module):
	name = 'DBus'
	# permissions file path
	permission_path = None
	# service file
	service_path = None
	# dbus_permissions
	own_users = []
	own_groups = []
	access_users = []
	access_groups = []
	# dbus service
	service_exe = None
	service_user = None

	#curses
	selected = 0

	def find(self):
		"""Try to find DBus configuration files."""
		if os.path.exists(os.path.join(config.paths['dbusconfdir'],'org.liberouter.netopeer2.conf')):
			self.permission_path = os.path.join(config.paths['dbusconfdir'],'org.liberouter.netopeer2.conf')
		else:
			try:
				open(os.path.join(config.paths['dbusconfdir'], 'org.liberouter.netopeer2.conf'), 'w').close()
				self.permission_path = os.path.join(config.paths['dbusconfdir'], 'org.liberouter.netopeer2.conf')
			except IOError:
				self.permission_path = None
				messages.append('netopeer DBus service permissions file not found. Specify path.')

		if os.path.exists(os.path.join(config.paths['dbusservices'],'org.liberouter.netopeer2.server.service')):
			self.service_path = os.path.join(config.paths['dbusservices'],'org.liberouter.netopeer2.server.service')
		else:
			try:
				open(os.path.join(config.paths['dbusservices'],'org.liberouter.netopeer2.server.service'), 'w').close()
				self.service_path = os.path.join(config.paths['dbusservices'],'org.liberouter.netopeer2.server.service')
			except IOError:
				self.service_path = None
				messages.append('netopeer DBus service autostart file not found. Specify path.')

		return(True)

	def get(self):
		if not self.permission_path:
			messages.append('DBus permission file location not specified.')
		else:
			self.own_users = []
			self.own_groups = []
			self.access_users = []
			self.access_groups = []

			try:
				dbus_doc = libxml2.parseFile(self.permission_path)
			except:
				return(True)
			dbus_ctxt = dbus_doc.xpathNewContext()
			u_own = dbus_ctxt.xpathEval('/busconfig/policy[@user and allow/@own = \'org.liberouter.netopeer2.server\']/@user')
			g_own = dbus_ctxt.xpathEval('/busconfig/policy[@group and allow/@own = \'org.liberouter.netopeer2.server\']/@group')
			u_access = dbus_ctxt.xpathEval('/busconfig/policy[@user and allow/@send_destination = \'org.liberouter.netopeer2.server\' and allow/@receive_sender = \'org.liberouter.netopeer2.server\']/@user')
			g_access = dbus_ctxt.xpathEval('/busconfig/policy[@group and allow/@send_destination = \'org.liberouter.netopeer2.server\' and allow/@receive_sender = \'org.liberouter.netopeer2.server\']/@group')

			# append all users that can own server
			for user in u_own:
				self.own_users.append(user.get_content())
			# append all groups that can own server
			for group in g_own:
				self.own_groups.append(group.get_content())
			# append all users that can interact with server
			for user in u_access:
				self.access_users.append(user.get_content())
			# append all groups that can interact with server
			for group in g_access:
				self.access_groups.append(group.get_content())

		if not self.service_path:
			messages.append('DBus service file location not specified.')
		else:
			netopeer_service = False
			dbus_service = open(self.service_path, 'r')

			for line in dbus_service:
				if 'Name=org.liberouter.netopeer2.server' in line:
					netopeer_service = True
				elif 'Exec=' == line[:len('Exec=')]:
					self.service_exe = line[len('Exec='):].strip()
				elif 'User=' == line[:len('User=')]:
					self.service_user = line[len('User='):].strip()

			dbus_service.close()

			if not self.service_exe:
				for module in self.all_modules:
					if module.name == 'Netopeer':
						self.service_exe = module.server_path
			if not self.service_user:
				if self.own_users:
					self.service_user = self.own_users[0]

			if not netopeer_service:
				messages.append('{s} file does not configure netopeer service.'.format(s = self.service_path))

		return(True)

	def update(self):
		if not self.permission_path:
			messages.append('DBus permission file location not specified.')
		else:
			dbus_doc = libxml2.newDoc('1.0')
			dbus_root = dbus_doc.newChild(None, 'busconfig', None)
			dbus_doc.setRootElement(dbus_root)
			dbus_doc.newDtd('busconfig', '-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN', 'http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd')
			for user in self.own_users:
				policy_node = dbus_root.newChild(None, 'policy', None)
				policy_node.newProp('user', user)
				allow_node = policy_node.newChild(None, 'allow', None)
				allow_node.newProp('own', 'org.liberouter.netopeer2.server')
			for group in self.own_groups:
				policy_node = dbus_root.newChild(None, 'policy', None)
				policy_node.newProp('group', group)
				allow_node = policy_node.newChild(None, 'allow', None)
				allow_node.newProp('own', 'org.liberouter.netopeer2.server')
			for user in self.access_users:
				policy_node = dbus_root.newChild(None, 'policy', None)
				policy_node.newProp('user', user)
				allow_node = policy_node.newChild(None, 'allow', None)
				allow_node.newProp('send_destination', 'org.liberouter.netopeer2.server')
				allow_node.newProp('receive_sender', 'org.liberouter.netopeer2.server')
			for group in self.access_groups:
				policy_node = dbus_root.newChild(None, 'policy', None)
				policy_node.newProp('group', group)
				allow_node = policy_node.newChild(None, 'allow', None)
				allow_node.newProp('send_destination', 'org.liberouter.netopeer2.server')
				allow_node.newProp('receive_sender', 'org.liberouter.netopeer2.server')

			dbus_permissions = open(self.permission_path, 'w')
			dbus_permissions.write(dbus_doc.serialize())
			dbus_permissions.close()

		if not self.service_path:
			messages.append('Dbus service file location not specified.')
		elif self.service_exe and self.service_user:
			dbus_service = open(self.service_path, 'w')
			dbus_service.write('[D-BUS Service]\n')
			dbus_service.write('Name=org.liberouter.netopeer2.server\n')
			dbus_service.write('Exec={s}\n'.format(s=self.service_exe))
			dbus_service.write('User={s}\n'.format(s=self.service_user))
			dbus_service.close()
		else:
			messages.append('Can not create valid service file. Not enough information specified.')

	def paint(self, window, focus, height, width):
		tools = []
		window.addstr('Path to DBus user permission for netopeer service:\n')
		if focus and self.selected == 0:
			window.addstr('{s}\n'.format(s = self.permission_path), curses.color_pair(1))
			tools.append(('e','edit'))
		else:
			window.addstr('{s}\n'.format(s = self.permission_path), curses.color_pair(2))
		window.addstr('Path to DBus autostart configuration for netopeer service:\n')
		if focus and self.selected == 1:
			window.addstr('{s}\n'.format(s = self.service_path), curses.color_pair(1))
			tools.append(('e','edit'))
		else:
			window.addstr('{s}\n'.format(s = self.service_path), curses.color_pair(2))
		window.addstr('\n')

		if self.own_users:
			if focus and self.selected == 2:
				window.addstr('Users that can own netopeer service:\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Users that can own netopeer service:\n', curses.color_pair(2))
		else:
			if focus and self.selected == 2:
				window.addstr('Currently there are no users that can own netopeer service. You can add some.\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Currently there are no users that can own netopeer service. You can add some.\n', curses.color_pair(2))

		for user in self.own_users:
			if focus and self.selected == (self.own_users.index(user)+3):
				window.addstr('{s}\n'.format(s = user), curses.color_pair(1))
				tools.append(('a','add'))
				tools.append(('d','delete'))
				tools.append(('e','edit'))
			else:
				window.addstr('{s}\n'.format(s = user), curses.color_pair(2))

		window.addstr('\n')
		if self.access_users:
			if focus and self.selected == (3+len(self.own_users)):
				window.addstr('Users that can access netopeer service:\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Users that can access netopeer service:\n', curses.color_pair(2))
		else:
			if focus and self.selected == (3+len(self.own_users)):
				window.addstr('Currently there are no users that can access netopeer service. You can add some.\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Currently there are no users that can access netopeer service. You can add some.\n', curses.color_pair(2))

		for user in self.access_users:
			if focus and self.selected == (self.access_users.index(user)+4+len(self.own_users)):
				window.addstr('{s}\n'.format(s = user), curses.color_pair(1))
				tools.append(('a','add'))
				tools.append(('d','delete'))
				tools.append(('e','edit'))
			else:
				window.addstr('{s}\n'.format(s = user), curses.color_pair(2))

		window.addstr('\n')
		if self.own_groups:
			if focus and self.selected == (4+len(self.own_users)+len(self.access_users)):
				window.addstr('Groups that can own netopeer service:\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Groups that can own netopeer service:\n', curses.color_pair(2))
		else:
			if focus and self.selected == (4+len(self.own_users)+len(self.access_users)):
				window.addstr('Currently there are no groups that can own netopeer service. You can add some.\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Currently there are no groups that can own netopeer service. You can add some.\n', curses.color_pair(2))

		for group in self.own_groups:
			if focus and self.selected == (self.own_groups.index(group)+5+len(self.own_users)+len(self.access_users)):
				window.addstr('{s}\n'.format(s = group), curses.color_pair(1))
				tools.append(('a','add'))
				tools.append(('d','delete'))
				tools.append(('e','edit'))
			else:
				window.addstr('{s}\n'.format(s = group), curses.color_pair(2))

		window.addstr('\n')
		if self.access_groups:
			if focus and self.selected == (5+len(self.own_users)+len(self.access_users)+len(self.own_groups)):
				window.addstr('Groups that can access netopeer service:\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Groups that can access netopeer service:\n', curses.color_pair(2))
		else:
			if focus and self.selected == (5+len(self.own_users)+len(self.access_users)+len(self.own_groups)):
				window.addstr('Currently there are no groups that can access netopeer service. You can add some.\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Currently there are no groups that can access netopeer service. You can add some.\n', curses.color_pair(2))

		for group in self.access_groups:
			if focus and self.selected == (self.access_groups.index(group)+6+len(self.own_users)+len(self.access_users)+len(self.own_groups)):
				window.addstr('{s}\n'.format(s = group), curses.color_pair(1))
				tools.append(('a','add'))
				tools.append(('d','delete'))
				tools.append(('e','edit'))
			else:
				window.addstr('{s}\n'.format(s = group), curses.color_pair(2))

		window.addstr('\n')
		window.addstr('DBus service\nExecutable that will be started by DBus:\n')
		if focus and self.selected == (6+len(self.own_users)+len(self.access_users)+len(self.own_groups)+len(self.access_groups)):
				window.addstr('{s}\n'.format(s=self.service_exe), curses.color_pair(1))
				tools.append(('e','edit'))
		else:
				window.addstr('{s}\n'.format(s=self.service_exe), curses.color_pair(2))

		window.addstr('Executable will run with priviledges of user:\n')
		if focus and self.selected == (7+len(self.own_users)+len(self.access_users)+len(self.own_groups)+len(self.access_groups)):
				window.addstr('{s}\n'.format(s=self.service_user), curses.color_pair(1))
				tools.append(('e','edit'))
		else:
				window.addstr('{s}\n'.format(s=self.service_user), curses.color_pair(2))


		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < (len(self.own_users)+len(self.access_users)+len(self.own_groups)+len(self.access_groups)+7):
			self.selected = self.selected+1
		elif key == ord('e'):
			if self.selected == 0:
				tmp_dbus_var = self.get_editable(1,0, stdscr, window, self.permission_path, curses.color_pair(1))
				if tmp_dbus_var and os.path.isfile(tmp_dbus_var):
					self.permission_path = tmp_dbus_var
					self.get()
				else:
					messages.append('{s} is not valid file.'.format(s = tmp_dbus_var))
			elif self.selected == 1:
				tmp_dbus_var = self.get_editable(3,0, stdscr, window, self.service_path, curses.color_pair(1))
				if tmp_dbus_var and os.path.isfile(tmp_dbus_var):
					self.service_path = tmp_dbus_var
					self.get()
				else:
					messages.append('{s} is not valid file.'.format(s = tmp_dbus_var))
			elif self.selected > 2 and self.selected <= (2+len(self.own_users)):
				pos = self.selected-3
				line = self.selected + 3
				tmp_dbus_var = self.get_editable(line,0, stdscr, window, self.own_users[pos], curses.color_pair(1))
				if tmp_dbus_var:
					self.own_users[pos] = tmp_dbus_var
				else:
					messages.append('{s} is not valid username.'.format(s = tmp_dbus_var))
			elif self.selected > (3+len(self.own_users)) and self.selected <= (3+len(self.own_users)+len(self.access_users)):
				pos = self.selected-4-len(self.own_users)
				line = self.selected + 4
				tmp_dbus_var = self.get_editable(line,0, stdscr, window, self.access_users[pos], curses.color_pair(1))
				if tmp_dbus_var:
					self.access_users[pos] = tmp_dbus_var
				else:
					messages.append('{s} is not valid username.'.format(s = tmp_dbus_var))
			elif self.selected > (4+len(self.own_users)+len(self.access_users)) and self.selected <= (4+len(self.own_users)+len(self.access_users)+len(self.own_groups)):
				pos = self.selected-5-len(self.own_users)-len(self.access_users)
				line = self.selected + 5
				tmp_dbus_var = self.get_editable(line,0, stdscr, window, self.own_groups[pos], curses.color_pair(1))
				if tmp_dbus_var:
					self.own_groups[pos] = tmp_dbus_var
				else:
					messages.append('{s} is not valid groupname.'.format(s = tmp_dbus_var))
			elif self.selected > (5+len(self.own_users)+len(self.access_users)+len(self.own_groups)) and self.selected <= (5+len(self.own_users)+len(self.access_users)+len(self.own_groups)+len(self.access_groups)):
				pos = self.selected-6-len(self.own_users)-len(self.access_users)-len(self.own_groups)
				line = self.selected + 6
				tmp_dbus_var = self.get_editable(line,0, stdscr, window, self.access_groups[pos], curses.color_pair(1))
				if tmp_dbus_var:
					self.access_groups[pos] = tmp_dbus_var
				else:
					messages.append('{s} is not valid groupname.'.format(s = tmp_dbus_var))
			elif self.selected == 6 + len(self.own_users) + len(self.access_users) + len(self.own_groups) + len(self.access_groups):
				tmp_dbus_var = self.get_editable(15+len(self.own_users) + len(self.access_users) + len(self.own_groups) + len(self.access_groups), 0, stdscr, window, self.service_exe, curses.color_pair(1))
				if os.access(tmp_dbus_var, os.X_OK):
					self.service_exe = tmp_dbus_var
				else:
					messages.append('{s} is not executable.'.format(s = tmp_dbus_var))
			elif self.selected == 7 + len(self.own_users) + len(self.access_users) + len(self.own_groups) + len(self.access_groups):
				tmp_dbus_var = self.get_editable(17+len(self.own_users) + len(self.access_users) + len(self.own_groups) + len(self.access_groups), 0, stdscr, window, self.service_user, curses.color_pair(1))
				if tmp_dbus_var:
					self.service_user = tmp_dbus_var
				else:
					messages.append('{s} is not valid username'.format(s = tmp_dbus_var))
			else:
				curses.flash()
		elif key == ord('a'):
			if self.selected >= 2 and self.selected <= (2+len(self.own_users)):
				line = 6 + len(self.own_users)
				tmp_dbus_var = self.get_editable(line,0, stdscr, window, '', curses.color_pair(1))
				if tmp_dbus_var:
					self.own_users.append(tmp_dbus_var)
				else:
					messages.append('{s} is not valid username.'.format(s = tmp_dbus_var))
			elif self.selected >= (3+len(self.own_users)) and self.selected <= (3+len(self.own_users)+len(self.access_users)):
				line = 8 + len(self.own_users) + len(self.access_users)
				tmp_dbus_var = self.get_editable(line,0, stdscr, window, '', curses.color_pair(1))
				if tmp_dbus_var:
					self.access_users.append(tmp_dbus_var)
				else:
					messages.append('{s} is not valid username.'.format(s = tmp_dbus_var))
			elif self.selected >= (4+len(self.own_users)+len(self.access_users)) and self.selected <= (4+len(self.own_users)+len(self.access_users)+len(self.own_groups)):
				line = 10 + len(self.own_users) + len(self.access_users) + len(self.own_groups)
				tmp_dbus_var = self.get_editable(line,0, stdscr, window, '', curses.color_pair(1))
				if tmp_dbus_var:
					self.own_groups.append(tmp_dbus_var)
				else:
					messages.append('{s} is not valid groupname.'.format(s = tmp_dbus_var))
			elif self.selected >= (5+len(self.own_users)+len(self.access_users)+len(self.own_groups)) and self.selected <= (5+len(self.own_users)+len(self.access_users)+len(self.own_groups)+len(self.access_groups)):
				line = 12 + len(self.own_users) + len(self.access_users) + len(self.own_groups) + len(self.access_groups)
				tmp_dbus_var = self.get_editable(line,0, stdscr, window, '', curses.color_pair(1))
				if tmp_dbus_var:
					self.access_groups.append(tmp_dbus_var)
				else:
					messages.append('{s} is not valid groupname.'.format(s = tmp_dbus_var))
			else:
				curses.flash()
		elif key == ord('d'):
			if self.selected > 2 and self.selected <= (2+len(self.own_users)):
				pos = self.selected-3
				self.own_users.remove(self.own_users[pos])
			elif self.selected > (3+len(self.own_users)) and self.selected <= (3+len(self.own_users)+len(self.access_users)):
				pos = self.selected-4-len(self.own_users)
				self.access_users.remove(self.access_users[pos])
			elif self.selected > (4+len(self.own_users)+len(self.access_users)) and self.selected <= (4+len(self.own_users)+len(self.access_users)+len(self.own_groups)):
				pos = self.selected-5-len(self.own_users)-len(self.access_users)
				self.own_groups.remove(self.own_groups[pos])
			elif self.selected > (5+len(self.own_users)+len(self.access_users)+len(self.own_groups)) and self.selected <= (5+len(self.own_users)+len(self.access_users)+len(self.own_groups)+len(self.access_groups)):
				pos = self.selected-6-len(self.own_users)-len(self.access_users)-len(self.own_groups)
				self.access_groups.remove(self.access_groups[pos])
			else:
				curses.flash()
		else:
			curses.flash()
		return(True)

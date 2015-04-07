#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import copy
import libxml2
import string
import ncmodule
import messages
import config

class netopeer_module:
	name = ''
	enabled = False

	def __init__(self, name='', enabled=False):
		self.name = name
		self.enabled = enabled

	def enable(self):
		self.enabled = True

	def disable(self):
		self.enabled = False

class nc_sshauth(ncmodule.ncmodule):
	name = 'SSH Authentication'

	netopeer_path = None
	netopeer_doc = None
	netopeer_ctxt = None

	client_keys = {}
	new_client_keys = {}

	# curses
	linewidth = 20
	selected = 0

	def find(self):
		libxml2.keepBlanksDefault(0)

		if not os.path.exists(config.paths['modulesdir']):
			messages.append('Netopeer modules directory not found.', 'error')
			return False

		module_path = os.path.join(config.paths['modulesdir'], 'Netopeer.xml')
		if not os.path.isfile(module_path):
			messages_append('Netopeer module configuration not found', 'error')
			return False

		module_doc = libxml2.parseFile(module_path)
		module_ctxt = module_doc.xpathNewContext()

		xpath_repo_type = module_ctxt.xpathEval('/device/repo/type')
		if not xpath_repo_type:
			messages.append('Module Netopeer is not valid, repo type is not specified', 'error')
			return False
		elif len(xpath_repo_type) != 1:
			messages.append('Module Netopeer is not valid, there are multiple repo types specified', 'error')
			return False
		elif xpath_repo_type[0].get_content() != 'file':
			messages.append('Module Netopeer is not valid, the repository is not a file', 'error')
			return False

		xpath_repo_path = module_ctxt.xpathEval('/device/repo/path')
		if not xpath_repo_path:
			messages.append('Module Netopeer is not valid, repo path is not specified', 'error')
			return False
		elif len(xpath_repo_path) != 1:
			messages.append('Module Netopeer is not valid, there are multiple repo paths specified', 'error')
			return False
		self.netopeer_path = xpath_repo_path[0].get_content()

		return True

	def get(self):
		if self.netopeer_path:

			if not os.path.exists(self.netopeer_path) or os.path.getsize(self.netopeer_path) == 0:
				datastore = open(self.netopeer_path, 'w')
				datastore.write('<?xml version="1.0" encoding="UTF-8"?>\n<datastores xmlns="urn:cesnet:tmc:datastores:file">\n  <running lock=""/>\n  <startup lock=""/>\n  <candidate modified="false" lock=""/>\n</datastores>')
				datastore.close()

			self.netopeer_doc = libxml2.parseFile(self.netopeer_path)
			self.netopeer_ctxt = self.netopeer_doc.xpathNewContext()
			self.netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
			self.netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')

			client_key_paths = self.netopeer_ctxt.xpathEval("/d:datastores/d:startup/n:netopeer/n:ssh/n:client-auth-keys/n:client-auth-key/n:path")
			if len(client_key_paths) > 0:
				for key_path in client_key_paths:
					key_username_nodes = self.netopeer_ctxt.xpathEval("/d:datastores/d:startup/n:netopeer/n:ssh/n:client-auth-keys/n:client-auth-key[n:path='{s}']/n:username".format(s=key_path.content))
					if len(key_username_nodes) == 0:
						messages.append('An authorized client SSH key configuration is invalid.', 'warning')
					else:
						self.client_keys[key_path.content] = key_username_nodes[0].content
						if 4+len(key_username_nodes[0].content)+len(key_path.content) > self.linewidth:
							self.linewidth = 4+len(key_username_nodes[0].content)+len(key_path.content)

			self.new_client_keys = copy.copy(self.client_keys)

		return True

	def update(self):
		self.netopeer_doc = libxml2.parseFile(self.netopeer_path)
		self.netopeer_ctxt = self.netopeer_doc.xpathNewContext()
		self.netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
		self.netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')

		# create the ssh container if not exists
		ssh_node = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:ssh')
		if len(ssh_node) == 0:
			netopeer_node = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer')
			ssh_node = netopeer_node[0].newChild(netopeer_node[0].ns(), 'ssh', None)
		else:
			ssh_node = ssh_node[0]

		changes = False
		if len(self.new_client_keys) != len(self.client_keys):
			changes = True
		for key_path in self.new_client_keys.keys():
			if not key_path in self.client_keys or self.client_keys[key_path] != self.new_client_keys[key_path]:
				changes = True

		if changes:
			client_auth_keys = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:ssh/n:client-auth-keys')
			if len(client_auth_keys) > 0:
				# unlink the whole node
				client_auth_keys[0].unlinkNode()
			client_auth_keys = ssh_node.newChild(ssh_node.ns(), 'client-auth-keys', None)
			for new_key_path in self.new_client_keys.keys():
				key_node = client_auth_keys.newChild(client_auth_keys.ns(), 'client-auth-key', None)
				key_node.newChild(key_node.ns(), 'path', new_key_path)
				key_node.newChild(key_node.ns(), 'username', self.new_client_keys[new_key_path])
			self.client_keys = copy.copy(self.new_client_keys)

		self.netopeer_doc.saveFormatFile(self.netopeer_path, 1)
		return True

	def unsaved_changes(self):
		if len(self.new_client_keys) != len(self.client_keys):
			return True
		for key_path in self.new_client_keys.keys():
			if not key_path in self.client_keys or self.client_keys[key_path] != self.new_client_keys[key_path]:
				return True

		return False

	def refresh(self, window, focus, height, width):
		return True

	def paint(self, window, focus, height, width):
		tools = []

		if focus:
			if self.selected == 0:
				tools.append(('ENTER','add key'))
			elif self.selected > 0:
				tools.append(('ENTER','edit'))
				tools.append(('DEL','delete'))

		try:
			window.addstr('Authorized public client SSH keys:\n')
			window.addstr('Add a public key'+' '*(self.linewidth-16)+'\n\n\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 0 else 0)
			if len(self.new_client_keys) == 0:
				window.addstr('None\n', curses.color_pair(0))
			else:
				for key_path in sorted(self.new_client_keys.keys()):
					window.addstr('"{u}": {p}'.format(u=self.new_client_keys[key_path],p=key_path)+' '*(self.linewidth-len(self.new_client_keys[key_path])-4-len(key_path))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected > 0 and key_path is sorted(self.new_client_keys.keys())[self.selected-1] else 0)
		except curses.error:
			pass

		return tools

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < len(self.new_client_keys):
			self.selected = self.selected+1
		elif key == curses.KEY_DC and self.selected > 0:
			if self.selected == len(self.new_client_keys):
				self.selected = self.selected-1

			selected_key_path = sorted(self.new_client_keys.keys())[self.selected-1]
			del self.new_client_keys[selected_key_path]
		elif key == ord('\n'):
			if self.selected == 0:
				window.addstr(1, 0, 'Path: '+' '*(self.linewidth-6))
				key_path = self.get_editable(1, 6, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
				if key_path == '':
					return True
				if not os.path.isfile(key_path):
					messages.append('"'+key_path+'" is not a file', 'error')
					return True
				try:
					key_file = open(key_path, 'r')
				except IOError as e:
					messages.append('File "'+key_path+'" open: '+e.strerror, 'error')
				key_data = key_file.read()
				key_file.close()
				if string.find(key_data, ' PRIVATE KEY-----\n') > -1:
					messages.append('"'+key_path+'" is a private key', 'error')
					return True
				if key_path in self.new_client_keys:
					messages.append('The key is already in the configuration', 'error')
					return True

				window.addstr(2, 0, 'Username: '+' '*(len(key_path)-4))
				key_username = self.get_editable(2, 10, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, False)
				if key_username == '':
					return True
				self.new_client_keys[key_path] = key_username

				if 4+len(key_path)+len(key_username) > self.linewidth:
					self.linewidth = 4+len(key_path)+len(key_username)

			elif self.selected > 0:
				window.addstr(1, 0, 'Path: '+' '*(self.linewidth-5))
				selected_key_path = sorted(self.new_client_keys.keys())[self.selected-1]
				key_path = self.get_editable(1, 6, stdscr, window, selected_key_path, curses.color_pair(1), True)
				if key_path == '':
					return True
				if key_path != selected_key_path:
					if not os.path.isfile(key_path):
						messages.append('"'+key_path+'" is not a file', 'error')
						return True
					try:
						key_file = open(key_path, 'r')
					except IOError as e:
						messages.append('File "'+key_path+'" open: '+e.strerror, 'error')
					key_data = key_file.read()
					key_file.close()
					if string.find(key_data, ' PRIVATE KEY-----\n') > -1:
						messages.append('"'+key_path+'" is a private key', 'error')
						return True

					self.new_client_keys[key_path] = self.new_client_keys[selected_key_path]
					del self.new_client_keys[selected_key_path]
				window.addstr(2, 0, 'Username: '+' '*(len(key_path)-4))
				key_username = self.get_editable(2, 10, stdscr, window, self.new_client_keys[key_path], curses.color_pair(1), False)
				if key_username == '':
					return True
				if key_username != self.new_client_keys[key_path]:
					self.new_client_keys[key_path] = key_username

				if 4+len(key_path)+len(key_username) > self.linewidth:
					self.linewidth = 4+len(key_path)+len(key_username)

		else:
			curses.flash()
		return True

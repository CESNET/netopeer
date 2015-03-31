#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import copy
import libxml2
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

class nc_netopeer(ncmodule.ncmodule):
	name = 'Netopeer'

	modules = []
	modules_maxlen = 0

	server_path = None
	modules_path = None

	netopeer_path = None
	netopeer_doc = None
	netopeer_ctxt = None

	client_keys = {}
	new_client_keys = {}

	# curses
	linewidth = 50
	selected = -1

	def find(self):
		for path in list(set([config.paths['bindir']] + (os.environ['PATH'].split(os.pathsep)))):
			if not self.server_path and os.path.exists(os.path.join(path,'netopeer-server')):
				self.server_path = os.path.join(path,'netopeer-server')

		if os.path.exists(config.paths['modulesdir']):
			self.modules_path = config.paths['modulesdir']
		else:
			messages.append('Netopeer modules directory not found. No module can be configured.', 'error')
		return(True)

	def get(self):
		if self.modules_path:
			for module_conf in os.listdir(self.modules_path):
				if os.path.isfile(os.path.join(self.modules_path, module_conf)):
					module_valid = True
					# get module name, everything before last dot
					module_name = module_conf.rsplit('.', 1)[0]
					module_doc = libxml2.parseFile(os.path.join(self.modules_path, module_conf))
					module_ctxt = module_doc.xpathNewContext()

					xpath_mainyin = module_ctxt.xpathEval('/device/data-models/model-main/path')
					if not xpath_mainyin:
						messages.append('Module {s} is not valid, main model path is missing'.format(s=module_name), 'warning')
						continue
					elif len(xpath_mainyin) != 1:
						messages.append('Module {s} is not valid, there are multiple main models'.format(s=module_name), 'warning')
						continue
					elif not os.path.exists(xpath_mainyin[0].get_content()):
						messages.append('Module {s} is not valid, main model file does not exist'.format(s=module_name), 'warning')
						continue

					xpath_maintransapi = module_ctxt.xpathEval('/device/data-models/model-main/transapi')
					if xpath_maintransapi and len(xpath_maintransapi) != 1:
						messages.append('Module {s} is not valid, there are multiple main transapi modules'.format(s=module_name), 'warning')
						continue
					elif xpath_maintransapi and not os.path.exists(xpath_maintransapi[0].get_content()):
						messages.append('Module {s} is not valid, main model transapi file does not exist'.format(s=module_name), 'warning')
						continue

					xpath_repo_type = module_ctxt.xpathEval('/device/repo/type')
					if not xpath_repo_type:
						messages.append('Module {s} is not valid, repo type is not specified'.format(s=module_name), 'warning')
						continue
					elif len(xpath_repo_type) != 1:
						messages.append('Module {s} is not valid, there are multiple repo types specified'.format(s=module_name), 'warning')
						continue
					elif xpath_repo_type[0].get_content() == 'file':
						xpath_repo_path = module_ctxt.xpathEval('/device/repo/path')
						if not xpath_repo_path:
							messages.append('Module {s} is not valid, repo path is not specified'.format(s=module_name), 'warning')
							continue
						elif len(xpath_repo_path) != 1:
							messages.append('Module {s} is not valid, there are multiple repo paths specified'.format(s=module_name), 'warning')
							continue
						# it is not necessary to test that the datastore exists
						if module_name == 'Netopeer':
							self.netopeer_path = xpath_repo_path[0].get_content()

					xpath_augmentyin = module_ctxt.xpathEval('/device/data-models/model/path')
					for yin in xpath_augmentyin:
						if not os.path.exists(yin.get_content()):
							messages.append('Module {s} is not valid, main model transapi file does not exist'.format(s=module_name), 'warning')
							module_valid = False
							break

					# do not allow manipulation with an internal or invalid modules
					if module_valid and not (module_name == 'Netopeer' or module_name == 'NETCONF-server'):
						self.modules.append(netopeer_module(module_name))
						if self.selected < 0:
							self.selected = 0
						if len(module_name) > self.modules_maxlen:
							self.modules_maxlen = len(module_name)

			if self.netopeer_path:
				if not os.path.exists(self.netopeer_path) or os.path.getsize(self.netopeer_path) == 0:
					datastore = open(self.netopeer_path, 'w')
					datastore.write('<?xml version="1.0" encoding="UTF-8"?>\n<datastores xmlns="urn:cesnet:tmc:datastores:file">\n  <running lock=""/>\n  <startup lock=""/>\n  <candidate modified="false" lock=""/>\n</datastores>')
					datastore.close()
				self.netopeer_doc = libxml2.parseFile(self.netopeer_path)
				self.netopeer_ctxt = self.netopeer_doc.xpathNewContext()
				self.netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
				self.netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')

				netopeer_allowed_modules = self.netopeer_ctxt.xpathEval("/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:enabled=\'true\']/n:name")
				netopeer_forbidden_modules = self.netopeer_ctxt.xpathEval("/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:enabled=\'false\']/n:name")

				for module_name in map(libxml2.xmlNode.get_content,netopeer_allowed_modules):
					if module_name in map(getattr, self.modules, ['name']*len(self.modules)):
						for module in self.modules:
							if module_name == module.name:
								module.enable()
								break
					else:
						missing_module = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:name = \'{s}\']/n:enabled'.format(s=module_name))
						missing_module[0].setContent('false')
						messages.append('Module {s} is not installed. Disabling in netopeer configuration.'.format(s=module_name), 'warning')

				for module_name in map(libxml2.xmlNode.get_content, netopeer_forbidden_modules):
					if module_name in map(getattr, self.modules, ['name']*len(self.modules)):
						for module in self.modules:
							if module_name == module.name:
								module.disable()
								break
					else:
						messages.append('Module {s} not installed. Skipping in netopeer configuration.'.format(s=module_name), 'warning')

				if config.options['ssh'] == 'yes':
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
			else:
				messages.append('Netopeer module not found, unable to manage modules', 'error')
				self.selected = -1
				self.modules = []

		return(True)

	def update(self):
		if not self.modules:
			return(True)

		# check netopeer config content
		modules_node = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules')
		if not modules_node:
			netopeer_node = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer')
			if not netopeer_node:
				startup_node = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup')
				if not startup_node:
					messages.append('Invalid content of the Netopeer startup datastore', 'error')
					return(False)
				netopeer_node = startup_node[0].newChild(None, 'netopeer', None)
				netopeer_node.newNs('urn:cesnet:tmc:netopeer:1.0', None)
			else:
				netopeer_node = netopeer_node[0]
			modules_node = netopeer_node.newChild(netopeer_node.ns(), 'modules', None)
		else:
			modules_node = modules_node[0]

		for module in self.modules:
			xml_module = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:name=\'{s}\']/n:enabled'.format(s=module.name))
			if not xml_module:
				# create it
				new_module = modules_node.newChild(modules_node.ns(), 'module', None)
				new_module.newChild(new_module.ns(), 'name', module.name)
				new_module.newChild(new_module.ns(), 'enabled', 'true' if module.enabled else 'false')
			else:
				# set it according to the current value
				xml_module[0].setContent('true' if module.enabled else 'false')

		if config.options['ssh'] == 'yes':
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
		return(True)

	def unsaved_changes(self):
		if not self.modules:
			return(False)

		for module in self.modules:
			xml_module = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:name=\'{s}\']/n:enabled'.format(s=module.name))
			if not xml_module:
				return(True)
			if (xml_module[0].getContent() == 'true' and not module.enabled) or\
					(xml_module[0].getContent() == 'false' and module.enabled):
				return(True)

		if len(self.new_client_keys) != len(self.client_keys):
			return(True)
		for key_path in self.new_client_keys.keys():
			if not key_path in self.client_keys or self.client_keys[key_path] != self.new_client_keys[key_path]:
				return(True)

		return(False)

	def refresh(self, window, focus, height, width):
		return(True)

	def paint(self, window, focus, height, width):
		tools = []

		if self.selected < len(self.modules):
			tools.append(('ENTER','enable/disable'))
		elif self.selected == len(self.modules):
			tools.append(('ENTER','add SSH key'))
		elif self.selected > len(self.modules):
			tools.append(('ENTER','edit'))
			tools.append(('DEL','delete'))

		try:
			window.addstr('The netopeer-server binary found in path:\n')
			window.addstr('{s}\n'.format(s=self.server_path), curses.color_pair(0) | curses.A_UNDERLINE)
			window.addstr('\n')

			window.addstr('Using modules instaled in path:\n')
			window.addstr('{s}\n'.format(s=self.modules_path), curses.color_pair(0) | curses.A_UNDERLINE)
			window.addstr('\n')

			window.addstr('Curently installed modules:\n')
			if self.modules_maxlen + 10 > self.linewidth:
				self.linewidth = self.modules_maxlen + 10
			for module in self.modules:
				msg = '{s}'.format(s=module.name)
				window.addstr(msg+' '*(self.linewidth - len(msg) - (7 if module.enabled else 8))+('enabled\n' if module.enabled else 'disabled\n'), curses.color_pair(0) | curses.A_REVERSE if focus and self.selected < len(self.modules) and module is self.modules[self.selected] else 0)

			window.addstr('\nTo (un)install Netopeer modules, use ')
			window.addstr('netopeer-manager(1)', curses.color_pair(0) | curses.A_UNDERLINE)
			window.addstr('.\n')

			if config.options['ssh'] == 'yes':
				window.addstr('\nPublic client SSH keys:\n')
				window.addstr('Add a public key'+' '*(self.linewidth-16)+'\n\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == len(self.modules) else 0)
				if len(self.new_client_keys) == 0:
					window.addstr('None\n', curses.color_pair(0))
				else:
					for key_path in sorted(self.new_client_keys.keys()):
						window.addstr('"{u}": {p}'.format(u=self.new_client_keys[key_path],p=key_path)+' '*(self.linewidth-len(self.new_client_keys[key_path])-4-len(key_path))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected > len(self.modules) and key_path is sorted(self.new_client_keys.keys())[self.selected-len(self.modules)-1] else 0)
		except curses.error:
			pass

		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < len(self.modules)+len(self.new_client_keys):
			self.selected = self.selected+1
		elif key == curses.KEY_DC and self.selected > len(self.modules):
			if self.selected == len(self.modules)+len(self.new_client_keys):
				self.selected = self.selected-1

			selected_key_path = sorted(self.new_client_keys.keys())[self.selected-len(self.modules)-1]
			del self.new_client_keys[selected_key_path]
		elif key == ord('\n'):
			if self.selected >= 0 and self.selected < len(self.modules):
				self.modules[self.selected].enabled = not self.modules[self.selected].enabled
			if self.selected == len(self.modules):
				window.addstr(11+len(self.modules), 0, 'Path: '+' '*(self.linewidth-6))
				key_path = self.get_editable(11+len(self.modules), 6, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
				if key_path == '':
					return(True)
				if not os.path.isfile(key_path):
					messages.append('"'+key_path+'" is not a file', 'error')
					return(True)
				if key_path in self.new_client_keys:
					messages.append('The key is already in the configuration', 'error')
					return(True)
				window.addstr(11+len(self.modules), 0, 'Username: '+' '*(len(key_path)-4))
				key_username = self.get_editable(11+len(self.modules), 10, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, False)
				if key_username == '':
					return(True)
				self.new_client_keys[key_path] = key_username

				if 4+len(key_path)+len(key_username) > self.linewidth:
					self.linewidth = 4+len(key_path)+len(key_username)

			if self.selected > len(self.modules):
				window.addstr(12+self.selected, 0, 'Path: '+' '*(self.linewidth-5))
				selected_key_path = sorted(self.new_client_keys.keys())[self.selected-len(self.modules)-1]
				key_path = self.get_editable(12+self.selected, 6, stdscr, window, selected_key_path, curses.color_pair(1), True)
				if key_path == '':
					return(True)
				if key_path != selected_key_path:
					if not os.path.isfile(key_path):
						messages.append('"'+key_path+'" is not a file', 'error')
						return(True)
					self.new_client_keys[key_path] = self.new_client_keys[selected_key_path]
					del self.new_client_keys[selected_key_path]
				window.addstr(12+self.selected, 0, 'Username: '+' '*(len(key_path)-4))
				key_username = self.get_editable(12+self.selected, 10, stdscr, window, self.new_client_keys[key_path], curses.color_pair(1), False)
				if key_username == '':
					return(True)
				if key_username != self.new_client_keys[key_path]:
					self.new_client_keys[key_path] = key_username

				if 4+len(key_path)+len(key_username) > self.linewidth:
					self.linewidth = 4+len(key_path)+len(key_username)

		else:
			curses.flash()
		return(True)

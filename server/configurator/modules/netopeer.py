#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import libxml2
import nc_module
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

class netopeer(nc_module.nc_module):
	name = 'Netopeer'

	modules = []
	server_path = None
	agent_path = None
	modules_path = None
	netopeer_path = None

	# curses
	selected = 0

	def find(self):
		for path in list(set([config.paths['bindir']] + (os.environ['PATH'].split(os.pathsep)))):
			if not self.server_path and os.path.exists(os.path.join(path,'netopeer-server')):
				self.server_path = os.path.join(path,'netopeer-server')
			if not self.agent_path and os.path.exists(os.path.join(path,'netopeer-agent')):
				self.agent_path = os.path.join(path,'netopeer-agent')

		if os.path.exists(config.paths['modulesdir']):
			self.modules_path = config.paths['modulesdir']
		else:
			messages.append('Netopeer modules directory not found. No modules can be configured.', 'warning')
		return(True)

	def get(self):
		netopeer_doc = None
		if self.modules_path:
			for module_conf in os.listdir(self.modules_path):
				if os.path.isfile(os.path.join(self.modules_path, module_conf)):
					# get module name, everything before last dot
					module_name = module_conf.rsplit('.', 1)[0]
					module_valid = True
					module_enabled = False
					module_doc = libxml2.parseFile(os.path.join(self.modules_path, module_conf))
					module_root = module_doc.getRootElement()
					node = module_root.children
					while node:
						if node.get_type() == 'element':
							if node.name == 'transapi':
								if not os.path.exists(node.get_content()):
									module_valid = False
							elif node.name == 'data-models':
								model = node.children
								while model:
									if model.get_type() == 'element':
										if model.name == 'model-main' or model.name == 'model':
											path = model.children
											while path:
												if path.get_type() == 'element' and path.name == 'path':
													if not os.path.exists(path.get_content()):
														module_valid = False
												path = path.nextElementSibling()
									model = model.nextElementSibling()
							elif node.name == 'repo':
								if node.prop('type') is None or node.prop('type') == 'file':
									path = node.children
									while path:
										if path.get_type() == 'element' and path.name == 'path':
											if not os.path.exists(path.get_content()):
												module_valid = False
											elif module_name == 'Netopeer':
												self.netopeer_path = path.get_content()
												netopeer_doc = libxml2.parseFile(path.get_content())
										path = path.nextElementSibling()

						node = node.nextElementSibling()

					if not module_valid:
						messages.append('Module {s} is not installed properly and will not be used: Some of referenced files does not exit.'.format(s=module_name), 'warning')
					elif module_name == 'Netopeer':
						continue
					else:
						self.modules.append(netopeer_module(module_name, module_enabled))

			if netopeer_doc:
				netopeer_ctxt = netopeer_doc.xpathNewContext()
				netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
				netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')
				netopeer_allowed_modules = netopeer_ctxt.xpathEval("/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:enabled=\'true\']/n:name")
				netopeer_forbidden_modules = netopeer_ctxt.xpathEval("/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:enabled=\'false\']/n:name")

				for module_name in map(libxml2.xmlNode.get_content,netopeer_allowed_modules):
					if module_name in map(getattr, self.modules, ['name']*len(self.modules)):
						for module in self.modules:
							if module_name == module.name:
								module.enable()
								break
					else:
						missing_module = netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:name = \'{s}\']/n:enabled'.format(s=module_name))
						missing_module[0].setContent('false')
						messages.append('Module \'{s}\' not installed. Disabling in netopeer configuration.'.format(s=module_name), 'warning')

				for module_name in map(libxml2.xmlNode.get_content, netopeer_forbidden_modules):
					if module_name in map(getattr, self.modules, ['name']*len(self.modules)):
						for module in self.modules:
							if module_name == module.name:
								module.disable()
								break
					else:
						messages.append('Module \'{s}\' not installed. Skipping in netopeer configuration.'.format(s=module_name), 'warning')
			else:
				self.modules = []

		return(True)

	def update(self):
		return(True)
		netopeer_doc = libxml2.newDoc('1.0')
		datastores = netopeer_doc.newChild(None, 'datastores', None)
		datastores.newNs('urn:cesnet:tmc:datastores:file', None)
		startup = datastores.newChild(None, 'startup', None)
		netopeer = startup.newChild(None, 'netopeer', None)
		netopeer.newNs('urn:cesnet:tmc:netopeer:1.0', None)
		modules = netopeer.newChild(None, 'modules', None)

		for module in self.modules:
				netopeer_module = modules.newChild(None, 'module', None)
				netopeer_module.newChild(None, 'name', module.name)
				if module.enabled:
					netopeer_module.newChild(None, 'enabled', 'true')
				else:
					netopeer_module.newChild(None, 'enabled', 'false')

		netopeer_doc.saveFormatFile(self.netopeer_path, 1)
		return(True)


	def paint(self, window, focus, height, width):
		tools = []
		window.addstr('The netopeer-server binary found in path:\n')
		window.addstr('{s}\n'.format(s=self.server_path))
		window.addstr('\n')

		window.addstr('The netopeer-agent binary found in path:\n')
		window.addstr('{s}\n'.format(s=self.agent_path))
		window.addstr('\n')

		window.addstr('Using modules instaled in path:\n')
		window.addstr('{s}\n'.format(s=self.modules_path))
		window.addstr('\n')

		window.addstr('Curently installed modules:\n')
		for module in self.modules:
			if focus and module is self.modules[self.selected]:
				window.addstr('{s}\n'.format(s=module.name), curses.color_pair(1))
				if module.enabled:
					tools.append(('c','disable'))
				else:
					tools.append(('c','enable'))
			else:
				if module.enabled:
					window.addstr('{s}\n'.format(s=module.name), curses.color_pair(3))
				else:
					window.addstr('{s}\n'.format(s=module.name), curses.color_pair(4))
		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
				self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < len(self.modules)-1:
				self.selected = self.selected+1
		elif key == ord('c'):
			if self.selected > 1 and self.selected < (len(self.modules)+2):
				self.modules[self.selected-2].enabled = not self.modules[self.selected-2].enabled
			else:
				curses.flash()
		else:
			curses.flash()
		return(True)

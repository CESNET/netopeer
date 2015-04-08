#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import copy
import string
import libxml2
import subprocess
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
	server_version = None
	modules_path = None

	netopeer_path = None
	netopeer_doc = None
	netopeer_ctxt = None

	# curses
	linewidth = 50
	selected = -1

	def find(self):
		for path in list(set([config.paths['bindir']] + (os.environ['PATH'].split(os.pathsep)))):
			if not self.server_path and os.path.exists(os.path.join(path,'netopeer-server')):
				self.server_path = os.path.join(path,'netopeer-server')
				try:
					p = subprocess.Popen([self.server_path, '-V'], stdout=subprocess.PIPE)
					version_line = p.communicate()[0].split(os.linesep)[0]
					ver_idx = string.find(version_line, 'version ')
					if ver_idx > -1:
						self.server_version = version_line[ver_idx+8:]
				except:
					pass

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
			else:
				messages.append('Netopeer module not found, unable to manage modules', 'error')
				self.selected = -1
				self.modules = []

		return(True)

	def update(self):
		if not self.modules or not self.netopeer_path:
			return(True)

		self.netopeer_doc = libxml2.parseFile(self.netopeer_path)
		self.netopeer_ctxt = self.netopeer_doc.xpathNewContext()
		self.netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
		self.netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')

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

		self.netopeer_doc.saveFormatFile(self.netopeer_path, 1)
		return(True)

	def unsaved_changes(self):
		if not self.modules:
			return(False)

		for module in self.modules:
			xml_module = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:name=\'{s}\']/n:enabled'.format(s=module.name))
			if not xml_module:
				if module.enabled:
					return(True)
			elif (xml_module[0].getContent() == 'true' and not module.enabled) or\
					(xml_module[0].getContent() == 'false' and module.enabled):
				return(True)

		return(False)

	def refresh(self, window, focus, height, width):
		return(True)

	def paint(self, window, focus, height, width):
		tools = []
		tools.append(('ENTER','enable/disable'))

		try:
			window.addstr('The netopeer-server binary found in path:\n')
			window.addstr('{s}'.format(s=self.server_path), curses.color_pair(0) | curses.A_UNDERLINE)
			window.addstr(' ver {s}\n'.format(s=self.server_version))
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

		except curses.error:
			pass

		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < len(self.modules)-1:
			self.selected = self.selected+1
		elif key == ord('\n'):
			if self.selected >= 0 and self.selected < len(self.modules):
				self.modules[self.selected].enabled = not self.modules[self.selected].enabled

		else:
			curses.flash()
		return(True)

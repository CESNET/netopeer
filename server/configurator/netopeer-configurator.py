#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import subprocess
import re
import libxml2

# variables set during configuration
#	BINDIR = '@bindir@'
#	MODULESDIR = '@MODULES_CFG_DIR@'
#	SYSCONFDIR = '@sysconfdir@'
#	DBUSCONFDIR = '@DBUSCONF@'
#	DBUSSERVICES = '@DBUSSERVICES@'
BINDIR = '/usr/local/bin/'
MODULESDIR = '/etc/liberouter/netopeer2/modules.conf.d/'
SYSCONFDIR = '/etc/'
DBUSCONFDIR = '/etc/dbus-1/system.d/'
DBUSSERVICES = '/usr/share/dbus-1/system-services/'


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

class netopeer_configuration:
	"""Top level class of netopeer-configuration script."""

	## variables
	# error and other messages
	messages = []
	# of paths to files and directories
	netopeer_servers = []
	netopeer_agents = []
	paths = {}
	# netopeer modules
	modules = []
	# sshd ports
	ports = []
	# dbus_permissions
	dbus_own_users = []
	dbus_own_groups = []
	dbus_access_users = []
	dbus_access_groups = []
	# dbus service
	dbus_service_exe = None
	dbus_service_user = None

	## methods
	def __init__(self):
		if not self.run_as_root():
			print('Script must be run with as a root.')
			exit(1)
		self.find_netopeer_binaries()
		self.find_netopeer_modules_path()
		self.find_sshd_config()
		self.find_dbus_config()
		self.find_nacm_config()
		self.get_netopeer_modules()
		self.get_ssh()
		self.get_dbus()

	def save_all(self):
		self.update_ssh()
		self.update_modules()
		self.update_dbus()

	def run_as_root(self):
		"""Script must be run as root user."""
		if os.geteuid() != 0:
			return(False)
		else:
			return(True)

	def find_netopeer_binaries(self):
		"""Try to find netopeer-server and netopeer-agent binaries."""
		for path in list(set([BINDIR] + (os.environ['PATH'].split(os.pathsep)))):
			if os.path.exists(os.path.join(path,'netopeer-server')):
				self.netopeer_servers.append(os.path.join(path,'netopeer-server'))
			if os.path.exists(os.path.join(path,'netopeer-agent')):
				self.netopeer_agents.append(os.path.join(path,'netopeer-agent'))

		self.paths['netopeer-server'] = self.netopeer_servers[0] if self.netopeer_servers else None
		self.paths['netopeer-agent'] = self.netopeer_agents[0] if self.netopeer_servers else None

		if self.netopeer_servers and self.netopeer_agents:
			return(True)
		else:
			return(False)

	def find_netopeer_modules_path(self):
		"""Try to find netopeer modules dictionary."""
		if os.path.exists(MODULESDIR):
			self.paths['modules_path'] = MODULESDIR
			return(True)
		else:
			self.messages.append('Netopeer modules directory not fount. No modules can be configured.')
			self.paths['modules_path'] = None
			return(False)

	def find_sshd_config(self):
		"""Try to find sshd binary and parse configuration location from its debug output."""
		#find ssh binary
		sshd_binary = None
		sshd_config = None

		for path in os.environ['PATH'].split(os.pathsep):
			if os.path.exists(os.path.join(path, 'sshd')) and os.access(os.path.join(path, 'sshd'), os.X_OK):
				sshd_binary = os.path.join(path, 'sshd')
				break

		if sshd_binary:
			sshd_output = subprocess.check_output(sshd_binary+' -d -d -t', stderr=subprocess.STDOUT, shell=True).split(os.linesep)
			for line in sshd_output:
				config = re.match(r'.*load_server_config:\s*filename\s*(.*)', line)
				if config is not None:
					sshd_config = config.group(1).strip()
					break

		if sshd_config and len(sshd_config) > 0:
			self.paths['sshd_config'] = sshd_config
		elif os.path.exists('/etc/ssh/sshd_config'):
			self.paths['sshd_config'] = '/etc/ssh/sshd_config'
		else:
			messages.append('Failed to find SSH daemon configuration file. Ports and subsystem can not be configured.')
			self.paths['sshd_config'] = None

		if self.paths['sshd_config']:
			return(True)
		else:
			return(False)

	def find_dbus_config(self):
		"""Try to find DBus configuration files."""
		if os.path.exists(DBUSCONFDIR+'/org.liberouter.netopeer2.conf'):
			self.paths['dbus_permissions'] = os.path.join(DBUSCONFDIR,'org.liberouter.netopeer2.conf')
		else:
			self.paths['dbus_permissions'] = None
			self.messages.append('netopeer DBus service permissions file not found. Specify path.')

		if os.path.exists(DBUSSERVICES+'/org.liberouter.netopeer2.server.service'):
			self.paths['dbus_service'] = os.path.join(DBUSSERVICES,'org.liberouter.netopeer2.server.service')
		else:
			self.paths['dbus_service'] = None
			self.messages.append('netopeer DBus service autostart file not found. Specify path.')

		if self.paths['dbus_permissions'] and self.paths['dbus_service']:
			return(True)
		else:
			return(False)

	def find_nacm_config(self):
		"""Try to find NACM datastore."""
		ncworkingdir = subprocess.check_output('pkg-config libnetconf --variable=ncworkingdir', shell=True).split(os.linesep)[0]
		if os.path.exists(os.path.join(ncworkingdir,'datastore-acm.xml')):
			self.paths['datastore_acm'] = os.path.join(ncworkingdir,'datastore-acm.xml')
			return(True)
		else:
			self.paths['datastore_acm'] = None
			return(False)

	def get_netopeer_modules(self):
		netopeer_doc = None
		if self.paths['modules_path'] is None:
			return(False)
		else:
			for module_conf in os.listdir(self.paths['modules_path']):
				if os.path.isfile(os.path.join(self.paths['modules_path'], module_conf)):
					# get module name, everything before last dot
					module_name = module_conf.rsplit('.', 1)[0]
					module_valid = True
					module_enabled = False
					module_doc = libxml2.parseFile(os.path.join(self.paths['modules_path'], module_conf))
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
												self.paths['netopeer_conf'] = path.get_content()
												netopeer_doc = libxml2.parseFile(path.get_content())
										path = path.nextElementSibling()

						node = node.nextElementSibling()

					if module_valid == False:
						self.messages.append('Module '+module_name+' is not installed properly and will not be used: Some of referenced files does not exit.')
					else:
						self.modules.append(netopeer_module(module_name, module_enabled))

			if netopeer_doc:
				netopeer_ctxt = netopeer_doc.xpathNewContext()
				netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
				netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')
				netopeer_allowed_modules = netopeer_ctxt.xpathEval("/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:module-allowed=\'true\']/n:module-name")
				netopeer_forbidden_modules = netopeer_ctxt.xpathEval("/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:module-allowed=\'false\']/n:module-name")

				for module_name in map(libxml2.xmlNode.get_content,netopeer_allowed_modules):
					if ([module for module in self.modules if module.name == module_name]):
						module.enable()
					else:
						missing_module = netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:module-name = \''+module_name+'\']/n:module-allowed')
						missing_module[0].setContent('false')
						self.messages.append('Module \''+module_name+'\' not installed. Disabling in netopeer configuration.')

				for module_name in map(libxml2.xmlNode.get_content, netopeer_forbidden_modules):
					if ([module for module in self.modules if module.name == netopeer_module]):
						module.disable()
					else:
						self.messages.append('Module \''+module_name+'\' not installed. Skipping in netopeer configuration.')
			else:
				self.modules = []
				return(False)

		return(True)

	def update_modules(self):
		netopeer_doc = libxml2.parseFile(self.paths['netopeer_conf'])
		netopeer_ctxt = netopeer_doc.xpathNewContext()
		netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
		netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')
		netopeer_modules = netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules')
		if len(netopeer_modules) != 1:
			return(False)

		for module in self.modules:
			netopeer_module_allowed = netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:module-name = \''+module.name+'\']/n:module-allowed')
			if len(netopeer_module_allowed) == 0:
				netopeer_module = netopeer_modules[0].newChild(None, 'module', None)
				netopeer_module.newChild(None, 'module-name', module.name)
				if module.enabled:
					netopeer_module.newChild(None, 'module-allowed', 'true')
				else:
					netopeer_module.newChild(None, 'module-allowed', 'false')
			elif len(netopeer_module_allowed) == 1:
				if module.enabled:
					netopeer_module_allowed[0].setContent('true')
				else:
					netopeer_module_allowed[0].setContent('false')
			else:
				pass

		if self.paths['netopeer_conf']: 
			netopeer_doc.saveFormatFile(self.paths['netopeer_conf'], 1)
			return(True)
		else:
			return(False)

	def get_ssh(self):
		self.ports = []
		self.subsystem = []
		subsystems = []
		for line in open(self.paths['sshd_config']):
			port = re.match(r'Port\s(\d*)', line)
			subsystem = re.match(r'Subsystem\s*netconf\s*(.*)', line)
			if port:
				port_int = int(port.group(1).strip())
				if not port_int in self.ports:
					self.ports.append(port_int)
			elif subsystem:
				subsystems.append(subsystem.group(1).strip())

		self.subsystem = subsystems[0] if subsystems else None

		if len(subsystems) > 1:
			messages.append('More than one netconf subsystem. SSH daemon will refuse to start.')
			return(False)

		return(True)

	def update_ssh(self):
		if not self.paths['sshd_config']:
			self.messages.append('Cannot write changes. Path to SSH daemon config is not specified.')
			return(False)
		else:
			sshd_file = open(self.paths['sshd_config'], 'r')
			sshd_lines = sshd_file.readlines()
			sshd_file.close()

			# remove all Ports and netconf Subsystems
			for line in sshd_lines:
				if re.match(r'Port\s\d*', line) or re.match(r'Subsystem\s*netconf\s*.*', line):
					sshd_lines.remove(line)

			# add configured ports and subsystem
			ports_done = False
			subsystem_done = False
			for line in sshd_lines:
				if (not ports_done) and re.match(r'#\s*Port', line):
					ports_done = True
					for port in self.ports:
						sshd_lines.insert(sshd_lines.index(line)+1, 'Port '+str(port)+'\n')
				elif (not subsystem_done) and re.match(r'#?\s*Subsystem', line):
					subsystem_done = True
					sshd_lines.insert(sshd_lines.index(line)+1, 'Subsystem netconf '+self.paths['netopeer-agent']+'\n')

			if not ports_done:
				for port in self.ports:
					sshd_lines.insert(sshd_lines.index(line)+1, 'Port '+str(port)+'\n')
			if not subsystem_done:
				sshd_lines.insert(sshd_lines.index(line)+1, 'Subsystem netconf '+selt.paths['netopeer-agent']+'\n')

			sshd_file = open(known_paths['sshd_config'], 'w')
			sshd_file.writelines(sshd_lines)
			sshd_file.close()
			return(True)

	def get_dbus(self):
		if not self.paths['dbus_permissions']:
			self.messages.append('DBus permission file location not specified.')
		else:
			self.dbus_own_users = []
			self.dbus_own_groups = []
			self.dbus_access_users = []
			self.dbus_access_groups = []

			dbus_doc = libxml2.parseFile(self.paths['dbus_permissions'])
			dbus_ctxt = dbus_doc.xpathNewContext()
			u_own = dbus_ctxt.xpathEval('/busconfig/policy[@user and allow/@own = \'org.liberouter.netopeer2.server\']/@user')
			g_own = dbus_ctxt.xpathEval('/busconfig/policy[@group and allow/@own = \'org.liberouter.netopeer2.server\']/@group')
			u_access = dbus_ctxt.xpathEval('/busconfig/policy[@user and allow/@send_destination = \'org.liberouter.netopeer2.server\' and allow/@receive_sender = \'org.liberouter.netopeer2.server\']/@user')
			g_access = dbus_ctxt.xpathEval('/busconfig/policy[@group and allow/@send_destination = \'org.liberouter.netopeer2.server\' and allow/@receive_sender = \'org.liberouter.netopeer2.server\']/@group')
			# append all users that can own server
			for user in u_own:
				self.dbus_own_users.append(user.get_content())
			# append all groups that can own server
			for group in g_own:
				self.dbus_own_groups.append(group.get_content())
			# append all users that can interact with server
			for user in u_access:
				self.dbus_access_users.append(user.get_content())
			# append all groups that can interact with server
			for group in g_access:
				self.dbus_access_groups.append(group.get_content())

		if not self.paths['dbus_service']:
			self.messages.append('DBus service file location not specified.')
		else:
			netopeer_service = False
			dbus_service = open(self.paths['dbus_service'], 'r')

			for line in dbus_service:
				if 'Name=org.liberouter.netopeer2.server' in line:
					netopeer_service = True
				elif 'Exec=' == line[:len('Exec=')]:
					self.dbus_service_exe = line[len('Exec='):]
				elif 'User=' == line[:len('User=')]:
					self.dbus_service_user = line[len('User='):]

			dbus_service.close()

			if not netopeer_service:
				self.messages.append(self.paths['dbus_service']+' file does not configure netopeer service.')
				return(False)

		return(True)

	def update_dbus(self):
		if not self.paths['dbus_permissions']:
			self.messages.append('DBus permission file location not specified.')
		else:
			dbus_doc = libxml2.xmlNewDoc('1.0')
			dbus_root = dbus_doc.newChild(None, 'busconfig', None)
			dbus_doc.setRootElement(dbus_root)
			dbus_doc.newDtd('busconfig', '-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN', 'http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd')
			for user in self.dbus_own_users:
				policy_node = dbus_root.newChild(None, 'policy', None)
				policy_node.newProp('user', user)
				allow_node = policy_node.newChild(None, 'allow', None)
				allow_node.newProp('own', 'org.liberouter.netopeer2.service')
			for group in self.dbus_own_groups:
				policy_node = dbus_root.newChild(None, 'policy', None)
				policy_node.newProp('group', group)
				allow_node = policy_node.newChild(None, 'allow', None)
				allow_node.newProp('own', 'org.liberouter.netopeer2.service')
			for user in self.dbus_access_users:
				policy_node = dbus_root.newChild(None, 'policy', None)
				policy_node.newProp('user', user)
				allow_node = policy_node.newChild(None, 'allow', None)
				allow_node.newProp('send_destination', 'org.liberouter.netopeer2.service')
				allow_node.newProp('receive_sender', 'org.liberouter.netopeer2.service')
			for group in self.dbus_access_users:
				policy_node = dbus_root.newChild(None, 'policy', None)
				policy_node.newProp('group', group)
				allow_node = policy_node.newChild(None, 'allow', None)
				allow_node.newProp('send_destination', 'org.liberouter.netopeer2.service')
				allow_node.newProp('receive_sender', 'org.liberouter.netopeer2.service')

			dbus_permissions = open(self.paths['dbus_permissions'], 'w')
			dbus_permissions.write(dbus_doc)
			dbus_permissions.close()

		if not self.paths['dbus_service']:
			self.messages.append('Dbus service file location not specified.')
		else:
			dbus_service = open(self.paths['dbus_service'], 'w')
			dbus_service.write('[D-BUS Service]\n')
			dbus_service.write('Name=org.liberoter.netopeer2.server\n')
			dbus_service.write('Exec='+self.dbus_service_exe+'\n')
			dbus_service.write('User='+self.dbus_service_user+'\n')
			dbus_service.close()

def get_using_editable_field(y, x, stdscr, window, variable, color = None):
	index = 0

	if color is None:
		color = curses.color_pair(0)

	while True:
		# how much to erase
		blocklen = len(variable)
		# repaint
		window.addstr(y,x, variable[:index], color)
		window.addstr(variable[index:index+1], color | curses.A_REVERSE)
		window.addstr(variable[index+1:], color)
		window.refresh()

		# get next key
		c = stdscr.getch()
		if c == ord('\n'):
			break
		elif c == 27: # ESC
			return('')
		elif c == curses.KEY_LEFT:
			if index > 0:
				index = index-1
		elif c == curses.KEY_RIGHT:
			if index < len(variable):
				index = index+1
		elif c == curses.KEY_BACKSPACE:
			if index > 0:
				variable = variable[:index-1] + variable[index:]
				index = index-1
		elif c == curses.KEY_DC:
			if index < (len(variable)-1):
				variable = variable[:index] + variable[index+1:]
			elif index == (len(variable)-1):
				variable = variable[:index]
				index = index-1
		elif c == curses.KEY_HOME:
			index = 0
		elif c == curses.KEY_END:
			index = len(variable)
		elif c > 31 and c < 256: # skip wierd characters in ASCII
			if index == 0:
				variable = chr(c)+variable
			else:
				variable = variable[:index]+chr(c)+variable[index:]
			index = index+1

		# erase
		for xx in range(x, blocklen+x):
			window.delch(y,xx)

	return(variable)

def cli(stdscr, config):
	#define colors
	# selected item
	curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
	# commands
	curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_BLUE)
	# enabled 
	curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_GREEN)
	# disabled
	curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_RED)
	# cursor invsible
	curses.curs_set(0)


	# LAYOUT
	#
	# +---------------------+------------------------------------------------+
	# |                     |                                                |
	# | Menu                | Content                                        |
	# | ( rest_y x menu_x ) | ( rest_y x rest_x )                            |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# |                     |                                                |
	# +---------------------+------------------------------------------------+
	# |                                                                      |
	# | Messages box (messages_y x maxx)                                     |
	# |                                                                      |
	# |                                                                      |
	# |                                                                      |
	# +----------------------------------------------------------------------+
	# | Available tools (tools_y x maxx)                                     |
	# +----------------------------------------------------------------------+
	#

	#get 'window' size
	(maxy,maxx) = stdscr.getmaxyx()
	# window sizes
	messages_x = maxx
	messages_y = 13
	tools_x = maxx
	tools_y = 3
	menu_x = 22
	menu_y = maxy-messages_y-tools_y
	content_x = maxx-menu_x
	content_y = maxy-messages_y-tools_y
	# left subwindow with menu items
	menu_wrapper = stdscr.derwin(menu_y,menu_x, 0,0)
	menu = menu_wrapper.derwin(menu_y-2,menu_x-4, 1,2)
	# right window with content depending on selected menu item
	content_wrapper = stdscr.derwin(content_y,content_x, 0,menu_x)
	content = content_wrapper.derwin(content_y-2,content_x-4, 1,2)
	# bottom window with error and other messages
	messages_wrapper = stdscr.derwin(messages_y,messages_x, maxy-tools_y-messages_y,0)
	messages = messages_wrapper.derwin(messages_y-2,messages_x-4, 1,2)
	# bottom line with avaliable tools/commands
	tools_wrapper = stdscr.derwin(tools_y,tools_x, maxy-tools_y,0)
	tools = tools_wrapper.derwin(tools_y-2,tools_x-4, 1,2)

	# Defined windows
	windows = ['Menu', 'Binary', 'Modules', 'SSH daemon', 'DBus', 'Access Control']
	# Menu options
	options = ['Introduction','Binary','Modules','SSH daemon','DBus','Access Control','Summary','Full log']
	menu_selected = 0
	window = 0
	binary_selected = 0
	module_selected = 0
	ssh_selected = 0
	dbus_selected = 0

	while True:
		# erase all windows
		menu.erase()
		content.erase()
		tools.erase()
		messages.erase()
		stdscr.erase()
		# paint window borders
		stdscr.box()
		menu_wrapper.box()
		content_wrapper.box()
		messages_wrapper.box()
		tools_wrapper.box()
	
		# Menu window
		for option in options:
			if option is options[menu_selected]:
				if windows[window] == 'Menu':
					menu.addstr(option+'\n', curses.color_pair(1))
				else:
					menu.addstr(option+'\n', curses.color_pair(2))
			else:	
				menu.addstr(option+'\n', curses.color_pair(0))
	
		# Content window
		if options[menu_selected] == 'Introduction':
			content.addstr('Welcome to netopeer configurator. Folowing steps will lead you through netopeer-server configuration.\n')
		elif options[menu_selected] == 'Binary':
			content.addstr('This netopeer server binary will be used:\n')
			if windows[window] == 'Binary' and binary_selected == 0:
				content.addstr(config.paths['netopeer-server']+'\n', curses.color_pair(1))
			else:
				content.addstr(config.paths['netopeer-server']+'\n', curses.color_pair(2))
			content.addstr('This netopeer agent binary will be used:\n')
			if windows[window] == 'Binary' and binary_selected == 1:
				content.addstr(config.paths['netopeer-agent']+'\n', curses.color_pair(1));
			else:
				content.addstr(config.paths['netopeer-agent']+'\n', curses.color_pair(2));
		elif options[menu_selected] == 'Modules':
			content.addstr('Using modules instaled in path:\n')
			content.addstr(config.paths['modules_path']+'\n')
			content.addstr('Curently installed modules:\n')
			for module in config.modules:
				if windows[window] == 'Modules' and module == config.modules[module_selected]:
					content.addstr(module.name+'\n', curses.color_pair(1))
				else:
					if module.enabled:
						content.addstr(module.name+'\n', curses.color_pair(3))
					else:
						content.addstr(module.name+'\n', curses.color_pair(4))
		elif options[menu_selected] == 'SSH daemon':
			content.addstr('Using SSH daemon configuration in file:\n')
			if windows[window] == 'SSH daemon' and ssh_selected == 0:
				content.addstr(config.paths['sshd_config']+'\n', curses.color_pair(1))
			else:
				content.addstr(config.paths['sshd_config']+'\n', curses.color_pair(2))
			content.addstr('As netconf subsystem will used netopeer-agent specified in \'Binary\' tab.\n')
			if config.ports:
				if windows[window] == 'SSH daemon' and ssh_selected == 1:
					content.addstr('Curently there are these port configured to be used by SSH daemon:\n', curses.color_pair(1))
				else:
					content.addstr('Curently there are these port configured to be used by SSH daemon:\n', curses.color_pair(2))
				for port in config.ports:
					if windows[window] == 'SSH daemon' and (config.ports.index(port)+2) == ssh_selected:
						content.addstr(str(port)+'\n', curses.color_pair(1))
					else:
						content.addstr(str(port)+'\n', curses.color_pair(2))
			else:
				if windows[window] == 'SSH daemon' and ssh_selected == 1:
					content.addstr('There are no configured ports for SSH daemon. The default one (22) will be used.', curses.color_pair(1))
				else:
					content.addstr('There are no configured ports for SSH daemon. The default one (22) will be used.', curses.color_pair(2))

		elif options[menu_selected] == 'DBus':
			content.addstr('Path to DBus user permission for netopeer service:\n')
			if windows[window] == 'DBus' and dbus_selected == 0:
				content.addstr(config.paths['dbus_permissions']+'\n', curses.color_pair(1))
			else:
				content.addstr(config.paths['dbus_permissions']+'\n', curses.color_pair(2))
			content.addstr('Path to DBus autostart configuration for netopeer service:\n')
			if windows[window] == 'DBus' and dbus_selected == 1:
				content.addstr(config.paths['dbus_service']+'\n', curses.color_pair(1))
			else:
				content.addstr(config.paths['dbus_service']+'\n', curses.color_pair(2))
			content.addstr('\n')

			if config.dbus_own_users:
				if windows[window] == 'DBus' and dbus_selected == 2:
					content.addstr('Users that can own netopeer service:\n', curses.color_pair(1))
				else:
					content.addstr('Users that can own netopeer service:\n', curses.color_pair(2))
			else:
				if windows[window] == 'DBus' and dbus_selected == 2:
					content.addstr('Currently there are no users that can own netopeer service. You add some.\n', curses.color_pair(1))
				else:
					content.addstr('Currently there are no users that can own netopeer service. You add some.\n', curses.color_pair(2))

			for user in config.dbus_own_users:
				if windows[window] == 'DBus' and dbus_selected == (config.dbus_own_users.index(user)+3):
					content.addstr(user+'\n', curses.color_pair(1))
				else:
					content.addstr(user+'\n', curses.color_pair(2))

			content.addstr('\n')
			if config.dbus_access_users:
				if windows[window] == 'DBus' and dbus_selected == (3+len(config.dbus_own_users)):
					content.addstr('Users that can access netopeer service:\n', curses.color_pair(1))
				else:
					content.addstr('Users that can access netopeer service:\n', curses.color_pair(2))
			else:
				if windows[window] == 'DBus' and dbus_selected == (3+len(config.dbus_own_users)):
					content.addstr('Currently there are no users that can access netopeer service. You add some.\n', curses.color_pair(1))
				else:
					content.addstr('Currently there are no users that can access netopeer service. You add some.\n', curses.color_pair(2))

			for user in config.dbus_access_users:
				if windows[window] == 'DBus' and dbus_selected == (config.dbus_access_users.index(user)+4+len(config.dbus_own_users)):
					content.addstr(user+'\n', curses.color_pair(1))
				else:
					content.addstr(user+'\n', curses.color_pair(2))

			content.addstr('\n')
			if config.dbus_own_groups:
				if windows[window] == 'DBus' and dbus_selected == (4+len(config.dbus_own_users)+len(config.dbus_access_users)):
					content.addstr('Groups that can own netopeer service:\n', curses.color_pair(1))
				else:
					content.addstr('Groups that can own netopeer service:\n', curses.color_pair(2))
			else:
				if windows[window] == 'DBus' and dbus_selected == (4+len(config.dbus_own_users)+len(config.dbus_access_users)):
					content.addstr('Currently there are no groups that can own netopeer service. You add some.\n', curses.color_pair(1))
				else:
					content.addstr('Currently there are no groups that can own netopeer service. You add some.\n', curses.color_pair(2))

			for group in config.dbus_own_groups:
				if windows[window] == 'DBus' and dbus_selected == (config.dbus_own_groups.index(group)+5+len(config.dbus_own_users)+len(config.dbus_access_users)):
					content.addstr(group+'\n', curses.color_pair(1))
				else:
					content.addstr(group+'\n', curses.color_pair(2))

			content.addstr('\n')
			if config.dbus_access_groups:
				if windows[window] == 'DBus' and dbus_selected == (5+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)):
					content.addstr('Groups that can access netopeer service:\n', curses.color_pair(1))
				else:
					content.addstr('Groups that can access netopeer service:\n', curses.color_pair(2))
			else:
				if windows[window] == 'DBus' and dbus_selected == (5+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)):
					content.addstr('Currently there are no groups that can access netopeer service. You add some.\n', curses.color_pair(1))
				else:
					content.addstr('Currently there are no groups that can access netopeer service. You add some.\n', curses.color_pair(2))

			for group in config.dbus_access_groups:
				if windows[window] == 'DBus' and dbus_selected == (config.dbus_access_groups.index(group)+6+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)):
					content.addstr(group+'\n', curses.color_pair(1))
				else:
					content.addstr(group+'\n', curses.color_pair(2))

		elif options[menu_selected] == 'Summary':
			content.addstr('Summary of whole configuration.\n')
			for key in config.paths:
				if config.paths[key]:
					content.addstr('Path to '+key+': '+config.paths[key]+'\n')
				else:
					content.addstr('Path to '+key+': <None>\n')
		elif options[menu_selected] == 'Full log':
			content.addstr('Full log or error and others messages:\n\n')
			for message in config.messages:
				content.addstr(message+'\n')


		# Messages window
		last_messages = config.messages[-(messages_y-2):]
		for message in reversed(last_messages):
			messages.addstr(message, curses.color_pair(4))
			if not message is last_messages[0]:
				messages.addstr('\n')
	
		# Tools widow
		tools.addstr('UP', curses.color_pair(1))
		tools.addstr(' - next ', curses.color_pair(0))
		tools.addstr('DOWN', curses.color_pair(1))
		tools.addstr(' - previous ', curses.color_pair(0))
		if windows[window] == 'Menu':
			if options[menu_selected] in windows:
				tools.addstr('TAB', curses.color_pair(1))
				tools.addstr(' - select ', curses.color_pair(0))
		else:
			tools.addstr('TAB', curses.color_pair(1))
			tools.addstr(' - back ', curses.color_pair(0))
		if windows[window] == 'Modules':
			tools.addstr('c', curses.color_pair(1))
			if config.modules[module_selected].enabled:
				tools.addstr(' - enable ', curses.color_pair(0))
			else:
				tools.addstr(' - disable ', curses.color_pair(0))
		if windows[window] == 'SSH daemon':
			if ssh_selected != 1:
				tools.addstr('e', curses.color_pair(1))
				tools.addstr(' - edit ', curses.color_pair(0))
			if ssh_selected > 0:
				tools.addstr('a', curses.color_pair(1))
				tools.addstr(' - add ', curses.color_pair(0))
			if ssh_selected > 1:
				tools.addstr('d', curses.color_pair(1))
				tools.addstr(' - delete ', curses.color_pair(0))
	
		stdscr.refresh()
		
		c = stdscr.getch()
		if c == ord('q'):
			break
		elif c == ord('\t'):
			if windows[window] == 'Menu':
				if options[menu_selected] in windows:
					window = windows.index(options[menu_selected])
				else:
					curses.flash()
			else:
				window = windows.index('Menu')
		elif windows[window] == 'Menu':
			if c == curses.KEY_UP and menu_selected > 0:
					menu_selected = menu_selected-1
			elif c == curses.KEY_DOWN and menu_selected < len(options)-1:
					menu_selected = menu_selected+1
			else:
				curses.flash()
		elif windows[window] == 'Binary':
			if c == curses.KEY_UP and binary_selected > 0:
					binary_selected = binary_selected-1
			elif c == curses.KEY_DOWN and binary_selected < 1:
					binary_selected = binary_selected+1
			elif c == ord('e'):
				if binary_selected == 0:
					tmp_netopeer_var = get_using_editable_field(1,0, stdscr, content, config.paths['netopeer-server'], curses.color_pair(1))
					if tmp_netopeer_var and os.path.isfile(tmp_netopeer_var) and os.access(tmp_netopeer_var, os.X_OK):
						config.paths['netopeer-server'] = tmp_netopeer_var
					else:
						config.messages.append(tmp_netopeer_var+' is not valid executable file.')

				else: 
					tmp_netopeer_var = get_using_editable_field(3,0, stdscr, content, config.paths['netopeer-agent'], curses.color_pair(1))
					if tmp_netopeer_var and os.path.isfile(tmp_netopeer_var) and os.access(tmp_netopeer_var, os.X_OK):
						 config.paths['netopeer-agent'] = tmp_netopeer_var
					else:
						config.messages.append(tmp_netopeer_var+' is not valid executable file.')
			else:
				curses.flash()
		elif windows[window] == 'Modules':
			if c == curses.KEY_UP and module_selected > 0:
				module_selected = module_selected-1
			elif c == curses.KEY_DOWN and module_selected < len(config.modules)-1:
				module_selected = module_selected+1
			elif c == ord('c'):
				config.modules[module_selected].enabled = not config.modules[module_selected].enabled
			else:
				curses.flash()
		elif windows[window] == 'SSH daemon':
			if c == curses.KEY_UP and ssh_selected > 0:
				ssh_selected = ssh_selected-1
			elif c == curses.KEY_DOWN and ssh_selected < (len(config.ports)+1):
				ssh_selected = ssh_selected+1
			elif c == ord('e') and ssh_selected == 0:
				# edit ssh config path
				tmp_ssh_var = get_using_editable_field(1,0, stdscr, content, config.paths['sshd_config'], curses.color_pair(1))
				if tmp_ssh_var:
					if os.path.exists(tmp_ssh_var):
						config.paths['sshd_config'] = tmp_ssh_var
						config.get_ssh()
					else:
						config.messages.append('\''+tmp_ssh_var+'\' is not valid file.')
			elif c == ord('e') and ssh_selected > 1:
				# edit port
				tmp_ssh_var = get_using_editable_field(ssh_selected+2,0, stdscr, content, str(config.ports[ssh_selected-2]), curses.color_pair(1))
				if tmp_ssh_var and tmp_ssh_var.isdigit() and int(tmp_ssh_var) in range(1,2**16):
					if int(tmp_ssh_var) in config.ports:
						config.messages.append('Port '+tmp_ssh_var+' already is in the list of configured ports.')
					else:
						config.ports[ssh_selected-2] = int(tmp_ssh_var)
				else:
					config.messages.append(tmp_ssh_var+' is not valid port number.')
			elif c == ord('a') and ssh_selected > 0:
				# add new port
				tmp_ssh_var = get_using_editable_field(len(config.ports)+4,0, stdscr, content, '', curses.color_pair(1))
				if tmp_ssh_var and tmp_ssh_var.isdigit() and int(tmp_ssh_var) in range(1,2**16):
					if int(tmp_ssh_var) in config.ports:
						config.messages.append('Port '+tmp_ssh_var+' already is in the list of configured ports.')
					else:
						config.ports.append(int(tmp_ssh_var))
				else:
					config.messages.append(tmp_ssh_var+' is not valid port number.')

			elif c == ord('d') and ssh_selected > 1:
				config.ports.remove(config.ports[ssh_selected-2])
				if ssh_selected > len(config.ports)+1:
					ssh_selected = ssh_selected-1
			else:
				curses.flash()
		elif windows[window] == 'DBus':
			if c == curses.KEY_UP and dbus_selected > 0:
				dbus_selected = dbus_selected-1
			elif c == curses.KEY_DOWN and dbus_selected < (len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)+len(config.dbus_access_groups)+5):
				dbus_selected = dbus_selected+1
			elif c == ord('e'):
				if dbus_selected == 0:
					tmp_dbus_var = get_using_editable_field(1,0, stdscr, content, config.paths['dbus_permissions'], curses.color_pair(1))
					if tmp_dbus_var and os.path.isfile(tmp_dbus_var):
						config.paths['dbus_permissions'] = tmp_dbus_var
						config.get_dbus()
					else:
						config.messages.append(tmp_dbus_var+' is not valid file.')
				elif dbus_selected == 1:
					tmp_dbus_var = get_using_editable_field(3,0, stdscr, content, config.paths['dbus_service'], curses.color_pair(1))
					if tmp_dbus_var and os.path.isfile(tmp_dbus_var):
						config.paths['dbus_service'] = tmp_dbus_var
						config.get_dbus()
					else:
						config.messages.append(tmp_dbus_var+' is not valid file.')
				elif dbus_selected > 2 and dbus_selected <= (2+len(config.dbus_own_users)):
					pos = dbus_selected-3
					line = dbus_selected + 3
					tmp_dbus_var = get_using_editable_field(line,0, stdscr, content, config.dbus_own_users[pos], curses.color_pair(1))
					if tmp_dbus_var:
						config.dbus_own_users[pos] = tmp_dbus_var
					else:
						config.message.append(tmp_dbus_var+' is not valid username.')
				elif dbus_selected > (3+len(config.dbus_own_users)) and dbus_selected <= (3+len(config.dbus_own_users)+len(config.dbus_access_users)):
					pos = dbus_selected-4-len(config.dbus_own_users)
					line = dbus_selected + 4
					tmp_dbus_var = get_using_editable_field(line,0, stdscr, content, config.dbus_access_users[pos], curses.color_pair(1))
					if tmp_dbus_var:
						config.dbus_access_users[pos] = tmp_dbus_var
					else:
						config.message.append(tmp_dbus_var+' is not valid username.')
				elif dbus_selected > (4+len(config.dbus_own_users)+len(config.dbus_access_users)) and dbus_selected <= (4+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)):
					pos = dbus_selected-5-len(config.dbus_own_users)-len(config.dbus_access_users)
					line = dbus_selected + 5
					tmp_dbus_var = get_using_editable_field(line,0, stdscr, content, config.dbus_own_groups[pos], curses.color_pair(1))
					if tmp_dbus_var:
						config.dbus_own_groups[pos] = tmp_dbus_var
					else:
						config.message.append(tmp_dbus_var+' is not valid groupname.')
				elif dbus_selected > (5+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)) and dbus_selected <= (5+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)+len(config.dbus_access_groups)):
					pos = dbus_selected-6-len(config.dbus_own_users)-len(config.dbus_access_users)-len(config.dbus_own_groups)
					line = dbus_selected + 6
					tmp_dbus_var = get_using_editable_field(line,0, stdscr, content, config.dbus_access_groups[pos], curses.color_pair(1))
					if tmp_dbus_var:
						config.dbus_access_groups[pos] = tmp_dbus_var
					else:
						config.message.append(tmp_dbus_var+' is not valid groupname.')
				else:
					curses.flash()
			elif c == ord('a'):
				if dbus_selected >= 2 and dbus_selected <= (2+len(config.dbus_own_users)):
					line = 6 + len(config.dbus_own_users)
					tmp_dbus_var = get_using_editable_field(line,0, stdscr, content, '', curses.color_pair(1))
					if tmp_dbus_var:
						config.dbus_own_users.append(tmp_dbus_var)
					else:
						config.messages.append(tmp_dbus_var+' is not valid username.')
				elif dbus_selected >= (3+len(config.dbus_own_users)) and dbus_selected <= (3+len(config.dbus_own_users)+len(config.dbus_access_users)):
					line = 8 + len(config.dbus_own_users) + len(config.dbus_access_users)
					tmp_dbus_var = get_using_editable_field(line,0, stdscr, content, '', curses.color_pair(1))
					if tmp_dbus_var:
						config.dbus_access_users.append(tmp_dbus_var)
					else:
						config.messages.append(tmp_dbus_var+' is not valid username.')
				elif dbus_selected >= (4+len(config.dbus_own_users)+len(config.dbus_access_users)) and dbus_selected <= (4+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)):
					line = 10 + len(config.dbus_own_users) + len(config.dbus_access_users) + len(config.dbus_own_groups)
					tmp_dbus_var = get_using_editable_field(line,0, stdscr, content, '', curses.color_pair(1))
					if tmp_dbus_var:
						config.dbus_own_groups.append(tmp_dbus_var)
					else:
						config.messages.append(tmp_dbus_var+' is not valid groupname.')
				elif dbus_selected >= (5+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)) and dbus_selected <= (5+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)+len(config.dbus_access_groups)):
					line = 12 + len(config.dbus_own_users) + len(config.dbus_access_users) + len(config.dbus_own_groups) + len(config.dbus_access_groups)
					tmp_dbus_var = get_using_editable_field(line,0, stdscr, content, '', curses.color_pair(1))
					if tmp_dbus_var:
						config.dbus_access_groups.append(tmp_dbus_var)
					else:
						config.messages.append(tmp_dbus_var+' is not valid groupname.')
				else:
					curses.flash()
			elif c == ord('d'):
				if dbus_selected > 2 and dbus_selected <= (2+len(config.dbus_own_users)):
					pos = dbus_selected-3
					config.dbus_own_users.remove(config.dbus_own_users[pos])
				elif dbus_selected > (3+len(config.dbus_own_users)) and dbus_selected <= (3+len(config.dbus_own_users)+len(config.dbus_access_users)):
					pos = dbus_selected-4-len(config.dbus_own_users)
					config.dbus_access_users.remove(config.dbus_access_users[pos])
				elif dbus_selected > (4+len(config.dbus_own_users)+len(config.dbus_access_users)) and dbus_selected <= (4+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)):
					pos = dbus_selected-5-len(config.dbus_own_users)-len(config.dbus_access_users)
					config.dbus_own_groups.remove(config.dbus_own_groups[pos])
				elif dbus_selected > (5+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)) and dbus_selected <= (5+len(config.dbus_own_users)+len(config.dbus_access_users)+len(config.dbus_own_groups)+len(config.dbus_access_groups)):
					pos = dbus_selected-6-len(config.dbus_own_users)-len(config.dbus_access_users)-len(config.dbus_own_groups)
					config.dbus_access_groups.remove(config.dbus_access_groups[pos])
				else:
					curses.flash()

			else:
				curses.flash()

if __name__ == '__main__':
	config = netopeer_configuration()
	curses.wrapper(cli, config)

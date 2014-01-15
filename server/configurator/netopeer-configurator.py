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

def check_user():
	# running as a root
	if os.geteuid() <> 0:
		print("Configurator must be run with root privileges.")
		exit(1)


def detect_paths():
	known_paths = {}
	# binaries 
	if os.path.exists(BINDIR+'/netopeer-server'):
		known_paths['netopeer-server'] = os.path.join(BINDIR,'netopeer-server')
	else:
		known_paths['netopeer-server'] = None
	if os.path.exists(BINDIR+'/netopeer-agent'):
		known_paths['netopeer-agent'] = os.path.join(BINDIR,'netopeer-agent')
	else:
		known_paths['netopeer-agent'] = None

	# modules
	if os.path.exists(MODULESDIR):
		known_paths['modules_path'] = MODULESDIR
	
	# SSH config
	sshd_config = None
	sshd_output = subprocess.check_output('sshd -d -d -t', stderr=subprocess.STDOUT, shell=True).split(os.linesep)
	for line in sshd_output:
		config = re.match(r'.*load_server_config:\s*filename\s*(.*)', line)
		if config is not None:
			sshd_config = config.group(1).strip()
			break

	if sshd_config is not None and len(sshd_config) > 0:
		known_paths['sshd_config'] = sshd_config
	elif os.path.exists('/etc/ssh/sshd_config'):
		known_paths['sshd_config'] = '/etc/ssh/sshd_config'

	# DBus
	if os.path.exists(DBUSCONFDIR+'/org.liberouter.netopeer2.conf'):
		known_paths['dbus_permissions'] = os.path.join(DBUSCONFDIR,'org.liberouter.netopeer2.conf')
	
	if os.path.exists(DBUSSERVICES+'/org.liberouter.netopeer2.server.service'):
		known_paths['dbus_service'] = os.path.join(DBUSSERVICES,'org.liberouter.netopeer2.server.service')

	# NACM datastore
	ncworkingdir = subprocess.check_output('pkg-config libnetconf --variable=ncworkingdir', shell=True).split(os.linesep)[0]
	if os.path.exists(os.path.join(ncworkingdir,'datastore-acm.xml')):
		known_paths['datastore_acm'] = os.path.join(ncworkingdir,'datastore-acm.xml')
	
	return(known_paths)

def find_modules(known_paths):
	modules = []
	netopeer_doc = None
	for module_conf in os.listdir(known_paths['modules_path']):
		module = {}
		if os.path.isfile(os.path.join(known_paths['modules_path'], module_conf)):
			# get module name, everything before last dot
			module['name'] = module_conf.rsplit('.', 1)[0]
			module['valid'] = True
			module['enabled'] = False
			module_doc = libxml2.parseFile(os.path.join(known_paths['modules_path'], module_conf))
			module_root = module_doc.getRootElement()
			node = module_root.children
			while node:
				if node.get_type() == 'element':
					if node.name == 'transapi':
						if not os.path.exists(node.get_content()):
							module['valid'] = False
					elif node.name == 'data-models':
						model = node.children
						while model:
							if model.get_type() == 'element':
								if model.name == 'model-main' or model.name == 'model':
									path = model.children
									while path:
										if path.get_type() == 'element' and path.name == 'path':
											if not os.path.exists(path.get_content()):
												module['valid'] = False
										path = path.nextElementSibling()
							model = model.nextElementSibling()
					elif node.name == 'repo':
						if node.prop('type') is None or node.prop('type') == 'file':
							path = node.children
							while path:
								if path.get_type() == 'element' and path.name == 'path':
									if not os.path.exists(path.get_content()):
										module['valid'] = False
									elif module['name'] == 'Netopeer':
										known_paths['netopeer_conf'] = path.get_content()
										netopeer_doc = libxml2.parseFile(path.get_content())
								path = path.nextElementSibling()
								
				node = node.nextElementSibling()

			if module['name'] == 'Netopeer':
				continue
			elif module['valid'] == False:
				print('Configuration of module '+module['name']+' is not correct. Module will not be used.')
			else:
				modules.append(module)

	if not netopeer_doc is None:
		netopeer_ctxt = netopeer_doc.xpathNewContext()
		netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
		netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')
		netopeer_modules = netopeer_ctxt.xpathEval("/d:datastores/d:startup/n:netopeer/n:modules/n:module")
		for netopeer_module in netopeer_modules:
			tmp_name = None
			tmp_allowed = False
			node = netopeer_module.children
			while node:
				if node.get_type() == 'element':
					if node.name == 'module-name':
						tmp_name = node.get_content()
					elif node.name == 'module-allowed':
						if node.get_content() == 'true':
							tmp_allowed = True
						else:
							tmp_allowed = False
				node = node.nextElementSibling()

			for module in modules:
				if module['name'] == tmp_name:
					 module['enabled'] = tmp_allowed
			
	else:
		print('Netopeer module not fount. Modules can not be configure without Netopeer module.')
		modules = []
	
	return(modules)

	
def update_modules(known_paths, modules):
	netopeer_doc = libxml2.parseFile(known_paths['netopeer_conf'])
	netopeer_ctxt = netopeer_doc.xpathNewContext()
	netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
	netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')
	netopeer_modules = netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules')
	if len(netopeer_modules) != 1:
		print('Multiple instances of element /d:datastores/d:startup/n:netopeer/n:modules. Configuration not updated.')
		return

	for module in modules:
		netopeer_module_allowed = netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:modules/n:module[n:module-name = \''+module['name']+'\']/n:module-allowed')
		if len(netopeer_module_allowed) == 0:
			netopeer_module = netopeer_modules[0].newChild(None, 'module', None)
			netopeer_module.newChild(None, 'module-name', module['name'])
			if module['enabled']:
				netopeer_module.newChild(None, 'module-allowed', 'true')
			else:
				netopeer_module.newChild(None, 'module-allowed', 'false')
		elif len(netopeer_module_allowed) == 1:
			if module['enabled'] == True:
				netopeer_module_allowed[0].setContent('true')
			else:
				netopeer_module_allowed[0].setContent('false')
		else:
			print('Multiple instances of module \''+module['name']+'\'. Not changing any of them.')
	
		netopeer_doc.saveFormatFile(known_paths['netopeer_conf'], 1)

def get_ssh(known_paths):
	ports = []
	subsystems = []
	for line in open(known_paths['sshd_config']):
			port = re.match(r'Port\s(\d*)', line)
			subsystem = re.match(r'Subsystem\s*netconf\s*(.*)', line)
			if port:
				ports.append(int(port.group(1).strip()))
			elif subsystem:
				subsystems.append(subsystem.group(1).strip())

	if len(subsystems) > 1:
		print('More than one netconf subsystem. SSH daemon will not start.')
	
	return(ports, subsystems[0] if subsystems else '')

def update_ssh(known_paths, ports, subsystem):
	sshd_file = open(known_paths['sshd_config'], 'r')
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
			for port in ports:
				sshd_lines.insert(sshd_lines.index(line)+1, 'Port '+str(port)+'\n')
		elif (not subsystem_done) and re.match(r'#?\s*Subsystem', line):
			subsystem_done = True
			sshd_lines.insert(sshd_lines.index(line)+1, 'Subsystem netconf '+known_paths['netopeer-agent']+'\n')

	if not ports_done:
		for port in ports:
			sshd_lines.insert(sshd_lines.index(line)+1, 'Port '+str(port)+'\n')
	if not subsystem_done:
		sshd_lines.insert(sshd_lines.index(line)+1, 'Subsystem netconf '+known_paths['netopeer-agent']+'\n')
	
	sshd_file = open(known_paths['sshd_config'], 'w')
	sshd_file.writelines(sshd_lines)
	sshd_file.close()
		

def cli(stdscr, known_paths, modules):
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
	#get 'window' size
	(maxy,maxx) = stdscr.getmaxyx()
	# left subwindow with menu items
	menu = stdscr.derwin(maxy-3,20, 0,0)
	# right window with content depending on selected menu item
	content = stdscr.derwin(maxy-3,maxx-20, 0,20)
	# bootom line with avaliable tools/commands
	tools = stdscr.derwin(3, maxx, maxy-3,0)

	binary_selected = 0

	# Defined windows
	windows = ['Menu', 'Binary', 'Modules', 'SSH daemon', 'DBus', 'Access Control']
	# Menu options
	options = ['Introduction','Binary','Modules','SSH daemon','DBus','Access Control','Summary']
	selected = 0
	window = 0
	module_selected = 0
	while True:
		# erase all windows
		menu.erase()
		content.erase()
		tools.erase()
		stdscr.erase()
		# paint window borders
		stdscr.box()
		menu.box()
		content.box()
		tools.box()
	
		# Menu window
		for option in options:
			if option is options[selected]:
				if windows[window] == 'Menu':
					menu.addstr(options.index(option)+1, 2, option, curses.color_pair(1))
				else:
					menu.addstr(options.index(option)+1, 2, option, curses.color_pair(2))
			else:	
				menu.addstr(options.index(option)+1, 2, option, curses.color_pair(0))
	
		# Content window
		if options[selected] == 'Introduction':
			content.addstr(1,1, 'Welcome to netopeer configurator. Folowing steps will lead you through netopeer-server configuration.')
		elif options[selected] == 'Binary':
			content.addstr(1,1, 'This netopeer server binary will be used:')
			if windows[window] == 'Binary' and binary_selected == 0:
				content.addstr(2,1, known_paths['netopeer-server'], curses.color_pair(1))
			else:
				content.addstr(2,1, known_paths['netopeer-server'], curses.color_pair(2))
			content.addstr(3,1, 'This netopeer agent binary will be used:')
			if windows[window] == 'Binary' and binary_selected == 1:
				content.addstr(4,1, known_paths['netopeer-agent'], curses.color_pair(1));
			else:
				content.addstr(4,1, known_paths['netopeer-agent'], curses.color_pair(2));
		elif options[selected] == 'Modules':
			content.addstr(1,1, 'Using modules instaled in path:')
			content.addstr(2,1, known_paths['modules_path'])
			content.addstr(4,1, 'Curently installed modules:')
			for module in modules:
				if windows[window] == 'Modules' and module == modules[module_selected]:
					content.addstr(modules.index(module)+5,1, module['name'], curses.color_pair(1))
				else:
					if module['enabled']:
						content.addstr(modules.index(module)+5,1, module['name'], curses.color_pair(3))
					else:
						content.addstr(modules.index(module)+5,1, module['name'], curses.color_pair(4))
		elif options[selected] == 'Summary':
			content.addstr(1,1, 'Summary of whole configuration.')
			for key in known_paths:
				content.addstr(known_paths.keys().index(key)+2,1, 'Path to '+key+': '+known_paths[key])
	
		# Tools widow
		tools.addstr(1,1, 'UP', curses.color_pair(1))
		tools.addstr(1,3, ' - next', curses.color_pair(0))
		tools.addstr(1,16, 'DOWN', curses.color_pair(1))
		tools.addstr(1,20, ' - previous', curses.color_pair(0))
		if windows[window] == 'Menu':
			tools.addstr(1,32, 'TAB', curses.color_pair(1))
			tools.addstr(1,35, ' - select', curses.color_pair(0))
		elif windows[window] == 'Modules':
			tools.addstr(1,32, 'TAB', curses.color_pair(1))
			tools.addstr(1,35, ' - back', curses.color_pair(0))
			tools.addstr(1,48, 'c', curses.color_pair(1))
			if modules[module_selected]['enabled']:
				tools.addstr(1,49, ' - enable', curses.color_pair(0))
			else:
				tools.addstr(1,49, ' - disable', curses.color_pair(0))
	
	
		stdscr.refresh()
		
		c = stdscr.getch()
		if c == ord('q'):
			break
		elif c == ord('\t'):
			if windows[window] == 'Menu':
				if options[selected] in windows:
					window = windows.index(options[selected])
				else:
					curses.flash()
			else:
				window = windows.index('Menu')
		elif windows[window] == 'Menu':
			if c == curses.KEY_UP and selected > 0:
					selected = selected-1
			elif c == curses.KEY_DOWN and selected < len(options)-1:
					selected = selected+1
			else:
				curses.flash()
		elif windows[window] == 'Binary':
			if c == curses.KEY_UP and binary_selected > 0:
					binary_selected = binary_selected-1
			elif c == curses.KEY_DOWN and binary_selected < 1:
					binary_selected = binary_selected+1
			elif c == ord('e'):
				curses.echo()
				if binary_selected == 0:
					curses.setsyx(1,1)
					content.cursyncup()
					content.refresh()
					known_paths['netopeer-server'] = content.getstr(2,1);
				else: 
					curses.setsyx(2,2)
					content.cursyncup()
					content.refresh()
					known_paths['netopeer-agent'] = content.getstr(4,1);
				curses.noecho()
			else:
				curses.flash()
		elif windows[window] == 'Modules':
			if c == curses.KEY_UP and module_selected > 0:
					module_selected = module_selected-1
			elif c == curses.KEY_DOWN and module_selected < len(modules)-1:
					module_selected = module_selected+1
			elif c == ord('c'):
				modules[module_selected]['enabled'] = not modules[module_selected]['enabled']
				update_modules(known_paths, modules)
			else:
				curses.flash()
	

if __name__ == '__main__':
	check_user()
	known_paths = detect_paths()
	modules = find_modules(known_paths)
	(ports, subsystem) = get_ssh(known_paths)
	ports = [22,23,2,830]
	update_ssh(known_paths, ports, subsystem)
	curses.wrapper(cli, known_paths, modules)

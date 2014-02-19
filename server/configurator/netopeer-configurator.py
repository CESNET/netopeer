#!/usr/bin/python
# -*- coding:utf-8 -*-

# standard modules 
import curses
import os

# netopeer configurator module base
from modules.nc_module import NCModuleError

# error messages
import modules.messages as messages

class netopeer_configuration:
	"""Top level class of netopeer-configuration script."""

	# configuration modules
	nc_modules = []

	def __init__(self):
		if not self.run_as_root():
			print('Script must be run with as a root.')
			exit(1)
		try:
			import modules.sshd
			self.nc_modules.append(modules.sshd.sshd())
		except ImportError as e:
			messages.append(str(e))
		except NCModuleError as e:
			messages.append(str(e))

		try:
			import modules.dbus
			self.nc_modules.append(modules.dbus.dbus())
		except ImportError as e:
			messages.append(str(e))
		except NCModuleError as e:
			messages.append(str(e))

		try:
			import modules.sock
			self.nc_modules.append(modules.sock.sock())
		except ImportError as e:
			messages.append(str(e))
		except NCModuleError as e:
			messages.append(str(e))

		try:
			import modules.nacm
			self.nc_modules.append(modules.nacm.nacm())
		except ImportError as e:
			messages.append(str(e))
		except NCModuleError as e:
			messages.append(str(e))

		try:
			import modules.netopeer
			self.nc_modules.append(modules.netopeer.netopeer())
		except ImportError as e:
			messages.append(str(e))
		except NCModuleError as e:
			messages.append(str(e))

	def save_all(self):
		for nc_module in self.nc_modules:
			nc_module.update()

	def run_as_root(self):
		"""Script must be run as root user."""
		if os.geteuid() != 0:
			return(False)
		else:
			return(True)

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
	# | Messages box (w_messages_y x maxx)                                     |
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
	w_messages_x = maxx
	w_messages_y = 13
	tools_x = maxx
	tools_y = 3
	menu_x = 22
	menu_y = maxy-w_messages_y-tools_y
	content_x = maxx-menu_x
	content_y = maxy-w_messages_y-tools_y
	# left subwindow with menu items
	menu_wrapper = stdscr.derwin(menu_y,menu_x, 0,0)
	menu = menu_wrapper.derwin(menu_y-2,menu_x-4, 1,2)
	# right window with content depending on selected menu item
	content_wrapper = stdscr.derwin(content_y,content_x, 0,menu_x)
	content = content_wrapper.derwin(content_y-2,content_x-4, 1,2)
	# bottom window with error and other messages
	w_messages_wrapper = stdscr.derwin(w_messages_y,w_messages_x, maxy-tools_y-w_messages_y,0)
	w_messages = w_messages_wrapper.derwin(w_messages_y-2,w_messages_x-4, 1,2)
	# bottom line with avaliable tools/commands
	tools_wrapper = stdscr.derwin(tools_y,tools_x, maxy-tools_y,0)
	tools = tools_wrapper.derwin(tools_y-2,tools_x-4, 1,2)

	# Defined windows
	windows = ['Menu', 'Content']
	window = 0
	# Menu options
	module_selected = 0
	module_tools = []

	while True:
		# erase all windows
		menu.erase()
		content.erase()
		tools.erase()
		w_messages.erase()
		stdscr.erase()
		# paint window borders
		stdscr.box()
		menu_wrapper.box()
		content_wrapper.box()
		w_messages_wrapper.box()
		tools_wrapper.box()

		# Menu window
		for module in config.nc_modules:
			if module is config.nc_modules[module_selected]:
				if windows[window] == 'Menu':
					menu.addstr(module.name+'\n', curses.color_pair(1))
				else:
					menu.addstr(module.name+'\n', curses.color_pair(2))
			else:	
				menu.addstr(module.name+'\n', curses.color_pair(0))

		# Content window
		focus = windows[window] == 'Content'
		module_tools = config.nc_modules[module_selected].paint(content, focus, content_y, content_x)

		# Messages window
		last_messages = messages.last(w_messages_y-2)
		for message in reversed(last_messages):
			w_messages.addstr(message, curses.color_pair(4))
			if not message is last_messages[0]:
				w_messages.addstr('\n')

		# Tools widow
		tools.addstr('UP', curses.color_pair(1))
		tools.addstr(' - next ', curses.color_pair(0))
		tools.addstr('DOWN', curses.color_pair(1))
		tools.addstr(' - previous ', curses.color_pair(0))
		if windows[window] == 'Menu':
			tools.addstr('TAB', curses.color_pair(1))
			tools.addstr(' - select ', curses.color_pair(0))
			tools.addstr('F10', curses.color_pair(1))
			tools.addstr(' - save ', curses.color_pair(0))
		else:
			tools.addstr('TAB', curses.color_pair(1))
			tools.addstr(' - back ', curses.color_pair(0))
			# Print module tools
			for (key,desc) in module_tools:
				tools.addstr(key, curses.color_pair(1))
				tools.addstr(' - %s ' % desc, curses.color_pair(0))

		stdscr.refresh()

		c = stdscr.getch()
		if c == ord('q'):
			break
		elif c == ord('\t'):
			window = (window + 1) % len(windows)
		elif windows[window] == 'Menu':
			if c == curses.KEY_UP and module_selected > 0:
				module_selected = module_selected-1
			elif c == curses.KEY_DOWN and module_selected < (len(config.nc_modules)-1):
				module_selected = module_selected+1
			elif c == curses.KEY_F10:
				config.save_all()
			else:
				curses.flash()
		elif windows[window] == 'Content':
			config.nc_modules[module_selected].handle(stdscr, content, content_y, content_x, c)


if __name__ == '__main__':
	config = netopeer_configuration()
	curses.wrapper(cli, config)

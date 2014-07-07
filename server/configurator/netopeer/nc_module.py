#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses

# netopeer configurator modules exception 
class NCModuleError(Exception):
	def __init__(self, name = '', errmsg = ''):
		if name:
			self.name = name
		else:
			self.name = '<unspecified>'
		if errmsg:
			self.errmsg = errmsg
		else:
			self.errmsg = '<unspecified>'

	def __str__(self):
		return(self.name+': '+self.errmsg)

class NCModuleOff(Exception):
	def __init__(self, name = ''):
		if name:
			self.name = name
		else:
			self.name = '<unspecified>'
		
		self.errmsg = 'Module '+self.name+' is turned off'

	def __str__(self):
		return(self.errmsg)
	

# base class for netopeer configurator modules
class nc_module:
	# every module should define its name
	name = None
	all_modules = []

	# call methods to find files and get current settings
	def __init__(self, modules = []):
		self.all_modules = modules
		if not self.find() or not self.get():
			raise(NCModuleError(self.name, 'Module init failed.'))
	
	# find configuration/binary files
	def find(self):
		return(True)

	# get current configuration
	def get(self):
		return(True)

	# write current configuration to files
	def update(self):
		return(True)
	
 	# refresh content window after save
	def refresh(self, window, focus, height, width):
		return(True)
	
	def get_editable(self, y, x, stdscr, window, variable, color = None):
		index = 0
	
		if color is None:
			color = curses.color_pair(0)
	
		while True:
			# how much to erase
			blocklen = len(variable)
			try:
				# repaint
				window.addstr(y,x, variable[:index], color)
				window.addstr(variable[index:index+1], color | curses.A_REVERSE)
				window.addstr(variable[index+1:], color)
				window.refresh()
			except curses.error:
				pass
		
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


#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import ncmodule
import config

class nc_cfgsystem(ncmodule.ncmodule):
	name = 'cfgsystem'
	sshd_config_path = None
	passauth_setting = None
	passauth_commented = False
	new_commented = False
	new_setting = None
	#delimiting indices in netopeer sshd_config of the whole PasswordAuthentication line
	starti = -1
	endi = -1

	#curses
	selected = 0

	def find(self):
		if os.path.exists(os.path.join(config.paths['cfgdir'],'sshd_config')):
			self.sshd_config_path = os.path.join(config.paths['cfgdir'],'sshd_config')
		else:
			messages.append('Netopeer sshd configuration file not found.', 'error')
			return(False)

		return(True)

	def get(self):
		if not self.sshd_config_path:
			return(False)
		try:
			sshd_config_file = open(self.sshd_config_path, 'r')
		except OSError:
			return(False)
		content = sshd_config_file.read()
		sshd_config_file.close()

		self.starti = content.find('\nPasswordAuthentication ');
		if self.starti == -1:
			self.starti = content.find('\n#PasswordAuthentication ');
			if self.starti == -1:
				return(True)
			self.passauth_commented = True
			self.new_commented = True
		self.starti += 1
		self.endi = content.find('\n', self.starti);
		self.passauth_setting = content[content.find(' ', self.starti)+1 : self.endi]
		self.new_setting = self.passauth_setting

		return(True)

	def update(self):
		if not self.sshd_config_path:
			return(False)
		if not self.passauth_commented and self.new_setting == self.passauth_setting:
			return(True)

		try:
			sshd_config_file = open(self.sshd_config_path, 'r')
		except IOError:
			return(False)
		content = sshd_config_file.read()
		sshd_config_file.close()

		try:
			sshd_config_file = open(self.sshd_config_path, 'w')
		except IOError:
			return(False)
		if not self.passauth_setting:
			sshd_config_file.write(content)
			if content[-1:] != '\n':
				sshd_config_file.write('\n')
			sshd_config_file.write('\n# To disable tunneled clear text passwords, change to no here!\n')
		else:
			sshd_config_file.write(content[:self.starti])
		sshd_config_file.write('PasswordAuthentication ' + self.new_setting)
		if not self.passauth_setting:
			sshd_config_file.write('\n')
		else:
			sshd_config_file.write(content[self.endi:])
		sshd_config_file.close()

		self.passauth_commented = False
		self.passauth_setting = self.new_setting
		self.endi = self.starti + len('PasswordAuthentication ') + len(self.new_setting)

		return(True)

	def unsaved_changes(self):
		if self.passauth_commented != self.new_commented or self.passauth_setting != self.new_setting:
			return(True)

		return(False)

	def paint(self, window, focus, height, width):
		tools = [('ENTER', 'set')]
		try:
			window.addstr('Netopeer sshd_config PasswordAuthentication value: ' + ('(commented) ' if self.new_commented else '') +\
				('none' if not self.new_setting else self.new_setting) + '\n')

			window.addstr('Password tunnelled send and local user authentication: ')
			if self.new_commented or not self.new_setting:
				window.addstr('yes (default)\n\n')
			else:
				if self.new_setting == 'yes' or self.new_setting == 'no':
					window.addstr(self.new_setting + '\n\n')
				else:
					window.addstr(self.new_setting + ' (invalid value)\n\n')

			window.addstr('Set to \"yes\"\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 0 else 0)
			window.addstr('Set to \"no\"\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 1 else 0)
		except curses.error:
			pass

		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < 1:
			self.selected = self.selected+1
		elif key == ord('\n'):
			self.new_commented = False
			if self.selected == 0:
				self.new_setting = 'yes'
			elif self.selected == 1:
				self.new_setting = 'no'
			else:
				curses.flash()
		else:
			curses.flash()
		return(True)

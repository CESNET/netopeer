#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import M2Crypto
import ncmodule
import messages
import signal
import subprocess
import shutil
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

class nc_crls(ncmodule.ncmodule):
	name = 'CRLs'

	stunnelpath = None
	crlpath = None
	crlpath_toedit = False
	crls = []
	line_len = len('Add a CRL')
	show_crl = False
	crls_toremove = []
	crls_toadd = []

	# curses
	selected = -2

	def find(self):
		self.stunnelpath = config.paths['cfgdir'] + '/stunnel_config'
		if not os.path.isfile(self.stunnelpath):
			messages.append('netopeer stunnel config file not found', 'error')
			self.stunnelpath = None
			return(False)
		self.crlpath = self.get_stunnel_config()
		if self.crlpath == None:
			return(False)
		return(True)

	def parse_crl(self, path):
		try:
			crl = M2Crypto.X509.load_crl(path)
		except (IOError, M2Crypto.X509.X509Error):
			crl = None
		if not crl:
			messages.append('Could not parse CRL \"' + path + '\"', 'warning')
			return None

		# learn the longest items and create the crl structure
		text = crl.as_text()
		# find issuer and get the string
		i = text.find('Issuer: ')
		if i == -1:
			messages.append('Could not parse CRL \"' + path + '\"', 'warning')
			return None
		issuer = text[i+8 : text.find('\n', i)]
		items = issuer.split('/')
		C, ST, L, O, OU, CN, EA = None, None, None, None, None, None, None

		for item in items:
			if item[:2] == 'C=':
				C = item[2:]
			if item[:3] == 'ST=':
				ST = item[3:]
			if item[:2] == 'L=':
				L = item[2:]
			if item[:2] == 'O=':
				O = item[2:]
			if item[:3] == 'OU=':
				OU = item[3:]
			if item[:3] == 'CN=':
				CN = item[3:]
			if item[:13] == 'emailAddress=':
				EA = item[13:]

		i = text.find('Last Update: ')
		if i == -1:
			messages.append('Could not parse CRL \"' + path + '\"', 'warning')
			return None
		VF = text[i+13 : text.find('\n', i)]

		i = text.find('Next Update: ')
		if i == -1:
			messages.append('Could not parse CRL \"' + path + '\"', 'warning')
			return None
		VT = text[i+13 : text.find('\n', i)]

		return((os.path.basename(path)[:-4], C, ST, L, O, OU, CN, EA, VF, VT))

	def set_stunnel_config(self, new_crlpath):
		if not self.stunnelpath:
			return(False)
		try:
			file = open(self.stunnelpath, 'r')
		except IOError:
			return(False)
		text = file.read()
		file.close()

		if text[:10] == 'CRLPath = ':
			starti = 10
			endi = text.find('\n', starti)
		else:
			starti = text.find('\nCRLpath = ')
			if starti > -1:
				starti += 11
				endi = text.find('\n', starti)

		try:
			file = open(self.stunnelpath, 'w')
		except IOError:
			return(False)
		if starti > -1:
			file.write(text[:starti])
			file.write(new_crlpath)
			file.write(text[endi:])
		else:
			file.write('CRLpath = ' + new_crlpath + '\n')
			file.write(text)
		file.close()

		return(True)

	def get_stunnel_config(self):
		if not self.stunnelpath:
			return(None)
		try:
			file = open(self.stunnelpath, 'r')
		except IOError:
			return(None)
		text = file.read()
		file.close()

		i = text.find('\nCRLpath = ')
		if i == -1:
			messages.append('stunnel config file does not define any CRL directory', 'error')
			return(None)
		i += 11
		crlpath = text[i : text.find('\n', i)]

		return(crlpath)

	def get(self):
		self.crls = []
		self.line_len = len('Add a CRL')
		if self.crlpath == None or not os.path.isdir(self.crlpath):
			return(False)
		if len(self.crlpath) > self.line_len:
			self.line_len = len(self.crlpath)
		for path in os.listdir(self.crlpath):
			if len(path) < 5 or path[-4:] != '.pem' or os.path.isdir(os.path.join(self.crlpath, path)):
				continue
			crl = self.parse_crl(os.path.join(self.crlpath, path))

			if crl:
				if len(crl[0]) > self.line_len:
					self.line_len = len(crl[0])
				self.crls.append(crl)

		self.crls.sort()
		return(True)

	def update(self):
		changes = False
		try:
			while len(self.crls_toremove) > 0:
				os.remove(self.crls_toremove.pop())
				changes = True
		except OSError, e:
			messages.append('Could not remove \"' + self.crls[self.selected][0] + '\": ' + e.strerror + '\n', 'error')

		try:
			while len(self.crls_toadd) > 0:
				path = self.crls_toadd.pop()
				shutil.copyfile(path, os.path.join(self.crlpath, os.path.basename(path)))
				changes = True
		except IOError as e:
			messages.append('Could not add \"' + path + '\": ' + e.strerror + '\n', 'error')

		if changes:
			if not os.path.exists(config.paths['crehash']):
				messages.append('Could not rehash the CRL directory with \"' + config.paths['crehash'] + '\", left inconsistent', 'error')
				return(False)
			try:
				FNULL = open(os.devnull, 'w')
				subprocess.check_call([config.paths['crehash'], self.crlpath], stdin = FNULL, stdout = FNULL, stderr = FNULL, shell = False)
				FNULL.close()
			except subprocess.CalledProcessError:
				messages.append('c_rehash failed, the CRL directory left inconsistent', 'error')
				return(False)
			stunnel_pidpath = config.paths['cfgdir'] + '/stunnel/stunnel.pid'
			if os.path.exists(stunnel_pidpath):
				try:
					pidfile = open(stunnel_pidpath, 'r')
					stunnelpid = int(pidfile.read())
					os.kill(stunnelpid, signal.SIGHUP)
				except (ValueError, IOError, OSError):
					messages.append('netopeer stunnel pid file found, but could not force config reload, changes may not take effect before stunnel restart', 'error')

		if self.crlpath_toedit:
			if not self.set_stunnel_config(self.crlpath):
				messages.append('Could not write the new stunnel CRL dir into config file', 'error')
				return(False)
			self.crlpath_toedit = False

		return(True)

	def unsaved_changes(self):
		if self.crlpath_toedit or len(self.crls_toadd) > 0 or len(self.crls_toremove) > 0:
			return(True)

		return(False)

	def refresh(self, window, focus, height, width):
		return self.get()

	def maddstrln(self, window, width, msg, attr = 0, force_len = 0):
		if len(msg) > width-2:
			window.addstr(msg[:width-6]+'...\n', attr)
		elif force_len > len(msg):
			window.addstr(msg, attr)
			window.addstr((' '*((force_len if force_len < width-3 else width-3)-len(msg))) + '\n', (attr ^ curses.A_UNDERLINE if attr & curses.A_UNDERLINE else attr))
		else:
			window.addstr(msg + '\n', attr)

	def paint(self, window, focus, height, width):
		tools = [('PGUP, PGDOWN', 'scrolling'), ('DEL', 'remove')]
		if not self.show_crl:
			tools.append(('ENTER', 'show'))
			if self.selected < height-7:
				crl_index = 0
			else:
				crl_index = ((self.selected+5) / (height-2)) * (height-2) - 5

			if crl_index == 0:
				crl_count = height-7;
				self.maddstrln(window, width, 'CRL certificates in:');
				self.maddstrln(window, width, self.crlpath, curses.color_pair(0) | curses.A_UNDERLINE | (curses.A_REVERSE if focus and self.selected == -2 else 0), self.line_len)
				self.maddstrln(window, width, '')
				self.maddstrln(window, width, 'Add a CRL', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == -1 else 0, self.line_len)
				self.maddstrln(window, width, '')
			else:
				crl_count = height-2;

			try:
				i = 0
				while crl_index+i < len(self.crls) and i < crl_count:
					self.maddstrln(window, width, self.crls[crl_index+i][0], curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == crl_index+i else 0, self.line_len)
					i += 1
				if len(self.crls) == 0:
					self.maddstrln(window, width, 'None')
			except curses.error:
				pass
		else:
			tools.append(('ENTER', 'hide'))
			crl = self.crls[self.selected]
			# C, ST, L, O, OU, CN, EA, VF, VT
			VF = crl[8]
			VT = crl[9]

			try:
				window.addstr(self.crls[self.selected][0] + '\n\n')
				window.addstr('Issuer\n')
				window.addstr('C:  ' + str(crl[1]) + '\n')
				window.addstr('ST: ' + str(crl[2]) + '\n')
				window.addstr('L:  ' + str(crl[3]) + '\n')
				window.addstr('O:  ' + str(crl[4]) + '\n')
				window.addstr('OU: ' + str(crl[5]) + '\n')
				window.addstr('CN: ' + str(crl[6]) + '\n')
				window.addstr('EA: ' + str(crl[7]) + '\n')

				window.addstr('\nValid from: ' + str(VF) + '\n');
				window.addstr('        to: ' + str(VT) + '\n');
			except curses.error:
				pass

		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and ((not self.show_crl and self.selected > -2) or (self.show_crl and self.selected > 0)):
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < len(self.crls)-1:
			self.selected = self.selected+1
		elif key == ord('\n'):
			if self.selected == -2:
				window.addstr(1, 0, ' '*(width-2))
				path = self.get_editable(1, 0, stdscr, window, self.crlpath, curses.color_pair(1), True)
				if path == '' or path == self.crlpath:
					return(True)
				self.crlpath = path
				self.crlpath_toedit = True
				self.get()
			elif self.selected == -1:
				window.erase()
				window.addstr('Absolute path: ')
				path = self.get_editable(0, 15, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
				if path == '':
					return(True)
				if os.path.exists(os.path.join(self.crlpath, os.path.basename(path))):
					messages.append('CRL \"' + os.path.basename(path)[:-4] + '\" already in the CRL directory', 'error')
					return(True)
				crl = self.parse_crl(path)

				if crl:
					self.crls.append(crl)
					self.crls.sort()
					self.crls_toadd.append(path)
			else:
				self.show_crl = not self.show_crl
		elif key == curses.KEY_DC and self.selected > -1:
			self.crls_toremove.append(os.path.join(self.crlpath, self.crls[self.selected][0]) + '.pem')
			del self.crls[self.selected]
			self.selected -= 1;
		elif key == curses.KEY_NPAGE and self.selected != len(self.crls)-1:
			if self.selected < 0:
				self.selected += height-3
			else:
				self.selected += height-2
			if self.selected > len(self.crls)-1:
				self.selected = len(self.crls)-1
		elif key == curses.KEY_PPAGE and self.selected != -2:
			self.selected -= height-2
			if self.selected < -2:
				self.selected = -2
		else:
			curses.flash()
		return(True)

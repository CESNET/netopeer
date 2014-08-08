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

	crlpath = None
	crls = []
	show_crl = False
	crls_toremove = []
	crls_toadd = []

	# curses
	selected = 0

	def find(self):
		if os.path.exists(config.paths['cfgdir']):
			self.crlpath = config.paths['cfgdir'] + '/stunnel/crl'
			if not os.access(self.crlpath, os.F_OK):
				messages.append('stunnel CRL directory does not exist, creating it', 'warning')
				if not os.mkdir(self.crlpath, 0700):
					messages.append('stunnel CRL directory could not be created', 'error')
					self.crlpath = None
		else:
			messages.append('netopeer configuration directory not found', 'error')
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

	def get(self):
		if self.crlpath:
			for path in os.listdir(self.crlpath):
				if len(path) < 5 or path[-4:] != '.pem' or os.path.isdir(os.path.join(self.crlpath, path)):
					continue
				crl = self.parse_crl(os.path.join(self.crlpath, path))

				if crl:
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

		return(True)

	def refresh(self, window, focus, height, width):
		return(True)

	def paint(self, window, focus, height, width):
		tools = [('DEL', 'remove'), ('INS', 'add')]
		if not self.show_crl:
			tools.append(('ENTER', 'show'))
			i = (self.selected / (height-2)) * (height-2)
			try:
				while i < len(self.crls):
					window.addstr(self.crls[i][0] + '\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == i else 0)
					i += 1
				if len(self.crls) == 0:
					window.addstr('None\n');
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
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < len(self.crls)-1:
			self.selected = self.selected+1
		elif key == ord('\n') and len(self.crls) > 0:
			self.show_crl = not self.show_crl
		elif key == curses.KEY_DC:
			self.crls_toremove.append(os.path.join(self.crlpath, self.crls[self.selected][0]) + '.pem')
			del self.crls[self.selected]
			if self.selected > 0:
				self.selected -= 1;
		elif key == curses.KEY_IC:
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
			curses.flash()
		return(True)

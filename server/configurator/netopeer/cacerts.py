#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import M2Crypto
import nc_module
import messages
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

class cacerts(nc_module.nc_module):
	name = 'CA Certificates'

	certspath = None
	certs = []
	show_cert = False
	certs_toremove = []
	certs_toadd = []

	# curses
	selected = 0

	def find(self):
		if os.path.exists(config.paths['cfgdir']):
			self.certspath = config.paths['cfgdir'] + '/stunnel/certs'
			if not os.access(self.certspath, os.F_OK):
				messages.append('stunnel certificate directory does not exist, creating it', 'warning')
				if not os.mkdir(self.certspath, 0700):
					messages.append('stunnel certificate directory could not be created', 'error')
					self.certspath = None
		else:
			messages.append('netopeer configuration directory not found', 'error')
		return(True)

	def parse_cert(self, path):
		try:
			cert = M2Crypto.X509.load_cert(path)
		except (IOError, M2Crypto.X509.X509Error):
			cert = None
		if not cert:
			messages.append('Could not parse certificate \"' + path + '\"', 'warning')
			return None

		# learn the longest items
		subject = cert.get_subject()
		subj_line_len = 0
		if subject.C and len(subject.C) > subj_line_len:
			subj_line_len = len(subject.C)
		if subject.ST and len(subject.ST) > subj_line_len:
			subj_line_len = len(subject.ST)
		if subject.L and len(subject.L) > subj_line_len:
			subj_line_len = len(subject.L)
		if subject.O and len(subject.O) > subj_line_len:
			subj_line_len = len(subject.O)
		if subject.OU and len(subject.OU) > subj_line_len:
			subj_line_len = len(subject.OU)
		if subject.CN and len(subject.CN) > subj_line_len:
			subj_line_len = len(subject.CN)
		if subject.emailAddress and len(subject.emailAddress) > subj_line_len:
			subj_line_len = len(subject.emailAddress)

		issuer = cert.get_subject()
		iss_line_len = 0
		if issuer.C and len(issuer.C) > iss_line_len:
			iss_line_len = len(issuer.C)
		if issuer.ST and len(issuer.ST) > iss_line_len:
			iss_line_len = len(issuer.ST)
		if issuer.L and len(issuer.L) > iss_line_len:
			iss_line_len = len(issuer.L)
		if issuer.O and len(issuer.O) > iss_line_len:
			iss_line_len = len(issuer.O)
		if issuer.OU and len(issuer.OU) > iss_line_len:
			iss_line_len = len(issuer.OU)
		if issuer.CN and len(issuer.CN) > iss_line_len:
			iss_line_len = len(issuer.CN)
		if issuer.emailAddress and len(issuer.emailAddress) > iss_line_len:
			iss_line_len = len(issuer.emailAddress)

		return((os.path.basename(path)[:-4], cert, subj_line_len, iss_line_len))

	def get(self):
		if self.certspath:
			for path in os.listdir(self.certspath):
				if len(path) < 5 or path[-4:] != '.pem' or os.path.isdir(os.path.join(self.certspath, path)):
					continue
				cert = self.parse_cert(os.path.join(self.certspath, path))

				if cert:
					self.certs.append(cert)

		self.certs.sort()
		return(True)

	def update(self):
		changes = False
		try:
			while len(self.certs_toremove) > 0:
				os.remove(self.certs_toremove.pop())
				changes = True
		except OSError, e:
			messages.append('Could not remove \"' + self.certs[self.selected][0] + '\": ' + e.strerror + '\n', 'error')

		try:
			while len(self.certs_toadd) > 0:
				path = self.certs_toadd.pop()
				shutil.copyfile(path, os.path.join(self.certspath, os.path.basename(path)[:-4] + '.pem'))
				changes = True
		except IOError as e:
			messages.append('Could not add \"' + path + '\": ' + e.strerror + '\n', 'error')

		if changes:
			if not os.path.exists(config.paths['crehash']):
				messages.append('Could not rehash the CA directory with \"' + config.paths['crehash'] + '\", left inconsistent', 'error')
				return(False)
			try:
				FNULL = open(os.devnull, 'w')
				subprocess.check_call([config.paths['crehash'], self.certspath], stdin = FNULL, stdout = FNULL, stderr = FNULL, shell = False)
				FNULL.close()
			except subprocess.CalledProcessError:
				messages.append('c_rehash failed, the CA directory left inconsistent', 'error')
				return(False)

		return(True)

	def refresh(self, window, focus, height, width):
		return(True)

	def paint(self, window, focus, height, width):
		tools = [('DEL', 'remove'), ('INS', 'add')]
		if not self.show_cert:
			tools.append(('ENTER', 'show'))
			i = (self.selected / (height-2)) * (height-2)
			try:
				while i < len(self.certs):
					window.addstr(self.certs[i][0] + '\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == i else 0)
					i += 1
				if len(self.certs) == 0:
					window.addstr('None')
			except curses.error:
				pass
		else:
			tools.append(('ENTER', 'hide'))
			cert = self.certs[self.selected][1]
			subject = cert.get_subject()
			issuer = cert.get_issuer()
			valid = cert.get_not_after()

			if height > 22:
				try:
					window.addstr(self.certs[self.selected][0] + '\n\n')
					window.addstr('Subject\n')
					if subject.C:
						window.addstr('C:  ' + subject.C + '\n')
					else:
						window.addstr('C:  None\n')
					if subject.ST:
						window.addstr('ST: ' + subject.ST + '\n')
					else:
						window.addstr('ST: None\n')
					if subject.L:
						window.addstr('L:  ' + subject.L + '\n')
					else:
						window.addstr('L:  None\n')
					if subject.O:
						window.addstr('O:  ' + subject.O + '\n')
					else:
						window.addstr('O:  None\n')
					if subject.OU:
						window.addstr('OU: ' + subject.OU + '\n')
					else:
						window.addstr('OU: None\n')
					if subject.CN:
						window.addstr('CN: ' + subject.CN + '\n')
					else:
						window.addstr('CN: None\n')
					if subject.emailAddress:
						window.addstr('EA: ' + subject.emailAddress + '\n')
					else:
						window.addstr('EA: None\n')

					window.addstr('\nIssuer\n')
					if issuer.C:
						window.addstr('C:  ' + issuer.C + '\n')
					else:
						window.addstr('C:  None\n')
					if issuer.ST:
						window.addstr('ST: ' + issuer.ST + '\n')
					else:
						window.addstr('ST: None\n')
					if issuer.L:
						window.addstr('L:  ' + issuer.L + '\n')
					else:
						window.addstr('L:  None\n')
					if issuer.O:
						window.addstr('O:  ' + issuer.O + '\n')
					else:
						window.addstr('O:  None\n')
					if issuer.OU:
						window.addstr('OU: ' + issuer.OU + '\n')
					else:
						window.addstr('OU: None\n')
					if issuer.CN:
						window.addstr('CN: ' + issuer.CN + '\n')
					else:
						window.addstr('CN: None\n')
					if issuer.emailAddress:
						window.addstr('EA: ' + issuer.emailAddress + '\n')
					else:
						window.addstr('EA: None\n')

					window.addstr('\nValid: ' + str(valid) + '\n')
				except curses.error:
					pass
			else:
				if width-2 < 24 or width-2 < 4 + self.certs[self.selected][2] + 1 + 4 + self.certs[self.selected][3] + 1:
					self.show_cert = False
					tools.pop()
					tools.append(('ENTER', 'show'))
					messages.append('Cannot show cert, terminal too small', 'warning')
					self.paint(window, focus, height, width)
				else:
					try:
						window.addstr(self.certs[self.selected][0] + '\n\n')
						msg = 'Subject'
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + 'Issuer\n')

						if subject.C:
							msg = 'C:  ' + subject.C
						else:
							msg = 'C:  None'
						if issuer.C:
							msg2 = 'C:  ' + issuer.C
						else:
							msg2 = 'C:  None'
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						if subject.ST:
							msg = 'ST: ' + subject.ST
						else:
							msg = 'ST:  None'
						if issuer.ST:
							msg2 = 'ST: ' + issuer.ST
						else:
							msg2 = 'ST:  None'
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						if subject.L:
							msg = 'L:  ' + subject.L
						else:
							msg = 'L:  None'
						if issuer.L:
							msg2 = 'L:  ' + issuer.L
						else:
							msg2 = 'L:  None'
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						if subject.O:
							msg = 'O:  ' + subject.O
						else:
							msg = 'O:  None'
						if issuer.O:
							msg2 = 'O:  ' + issuer.O
						else:
							msg2 = 'O:  None'
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						if subject.OU:
							msg = 'OU: ' + subject.OU
						else:
							msg = 'OU: None'
						if issuer.OU:
							msg2 = 'OU: ' + issuer.OU
						else:
							msg2 = 'OU: None'
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						if subject.CN:
							msg = 'CN: ' + subject.CN
						else:
							msg = 'CN: None'
						if issuer.CN:
							msg2 = 'CN: ' + issuer.CN
						else:
							msg2 = 'CN: None'
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						if subject.emailAddress:
							msg = 'EA: ' + subject.emailAddress
						else:
							msg = 'EA: None'
						if issuer.emailAddress:
							msg2 = 'EA: ' + issuer.emailAddress
						else:
							msg2 = 'EA: None'
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						window.addstr('\nValid: ' + str(valid) + '\n');
					except curses.error:
						pass

		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < len(self.certs)-1:
			self.selected = self.selected+1
		elif key == ord('\n') and len(self.certs) > 0:
			self.show_cert = not self.show_cert
		elif key == curses.KEY_DC:
			self.certs_toremove.append(os.path.join(self.certspath, self.certs[self.selected][0]) + '.pem')
			del self.certs[self.selected]
			if self.selected > 0:
				self.selected -= 1;
		elif key == curses.KEY_IC:
			window.erase()
			window.addstr('Absolute path: ')
			path = self.get_editable(0, 15, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
			if path == '':
				return(True)
			if os.path.exists(os.path.join(self.certspath, os.path.basename(path))):
				messages.append('Certificate \"' + os.path.basename(path)[:-4] + '\" already in the CA directory', 'error')
				return(True)
			cert = self.parse_cert(path)

			if cert:
				self.certs.append(cert)
				self.certs.sort()
				self.certs_toadd.append(path)
		else:
			curses.flash()
		return(True)

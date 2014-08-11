#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import M2Crypto
import ncmodule
import messages
import subprocess
import signal
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

class nc_cacerts(ncmodule.ncmodule):
	name = 'CA Certificates'

	stunnelpath = None
	certspath = None
	certspath_toedit = False
	certs = []
	line_len = len('Add a certificate')
	show_cert = False
	certs_toremove = []
	certs_toadd = []

	# curses
	selected = -2

	def find(self):
		self.stunnelpath = config.paths['cfgdir'] + '/stunnel_config'
		if not os.path.isfile(self.stunnelpath):
			messages.append('netopeer stunnel config file not found', 'error')
			self.stunnelpath = None
			return(False)
		self.certspath = self.get_stunnel_config()
		if self.certspath == None:
			return(False)
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

	def set_stunnel_config(self, new_certspath):
		if not self.stunnelpath:
			return(False)
		try:
			file = open(self.stunnelpath, 'r')
		except IOError:
			return(False)
		text = file.read()
		file.close()

		if text[:9] == 'CAPath = ':
			starti = 9
			endi = text.find('\n', starti)
		else:
			starti = text.find('\nCApath = ')
			if starti > -1:
				starti += 10
				endi = text.find('\n', starti)

		try:
			file = open(self.stunnelpath, 'w')
		except IOError:
			return(False)
		if starti > -1:
			file.write(text[:starti])
			file.write(new_certspath)
			file.write(text[endi:])
		else:
			file.write('CApath = ' + new_certspath + '\n')
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

		i = text.find('\nCApath = ')
		if i == -1:
			messages.append('stunnel config file does not define any trusted CA directory', 'error')
			return(None)
		i += 10
		certspath = text[i : text.find('\n', i)]

		return(certspath)

	def get(self):
		self.certs = []
		self.line_len = len('Add a certificate')
		if self.certspath == None or not os.path.isdir(self.certspath):
			return(False)
		if len(self.certspath) > self.line_len:
			self.line_len = len(self.certspath)
		for path in os.listdir(self.certspath):
			if len(path) < 5 or path[-4:] != '.pem' or os.path.isdir(os.path.join(self.certspath, path)):
				continue
			cert = self.parse_cert(os.path.join(self.certspath, path))

			if cert:
				if len(cert[0]) > self.line_len:
					self.line_len = len(cert[0])
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
			# rehash cert dir and tell stunnel to reload it
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
			stunnel_pidpath = config.paths['cfgdir'] + '/stunnel/stunnel.pid'
			if os.path.exists(stunnel_pidpath):
				try:
					pidfile = open(stunnel_pidpath, 'r')
					stunnelpid = int(pidfile.read())
					os.kill(stunnelpid, signal.SIGHUP)
				except (ValueError, IOError, OSError):
					messages.append('netopeer stunnel pid file found, but could not force config reload, changes may not take effect before stunnel restart', 'error')

		if self.certspath_toedit:
			if not self.set_stunnel_config(self.certspath):
				messages.append('Could not write the new stunnel trusted CA dir into config file', 'error')
				return(False)
			self.certspath_toedit = False

		return(True)

	def unsaved_changes(self):
		if self.certspath_toedit or len(self.certs_toadd) > 0 or len(self.certs_toremove) > 0:
			return(True)

		return (False)

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
		if not self.show_cert:
			tools.append(('ENTER', 'show'))
			if self.selected < height-7:
				cert_index = 0
			else:
				cert_index = ((self.selected+5) / (height-2)) * (height-2) - 5

			if cert_index == 0:
				cert_count = height-7;
				self.maddstrln(window, width, 'Trusted CA certificates in:');
				self.maddstrln(window, width, self.certspath, curses.color_pair(0) | curses.A_UNDERLINE | (curses.A_REVERSE if focus and self.selected == -2 else 0), self.line_len)
				self.maddstrln(window, width, '')
				self.maddstrln(window, width, 'Add a certificate', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == -1 else 0, self.line_len)
				self.maddstrln(window, width, '')
			else:
				cert_count = height-2;

			try:
				i = 0
				while cert_index+i < len(self.certs) and i < cert_count:
					self.maddstrln(window, width, self.certs[cert_index+i][0], curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == cert_index+i else 0, self.line_len)
					i += 1
				if len(self.certs) == 0:
					self.maddstrln(window, width, 'None')
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
					window.addstr('C:  ' + str(subject.C) + '\n')
					window.addstr('ST: ' + str(subject.ST) + '\n')
					window.addstr('L:  ' + str(subject.L) + '\n')
					window.addstr('O:  ' + str(subject.O) + '\n')
					window.addstr('OU: ' + str(subject.OU) + '\n')
					window.addstr('CN: ' + str(subject.CN) + '\n')
					window.addstr('EA: ' + str(subject.emailAddress) + '\n')

					window.addstr('\nIssuer\n')
					window.addstr('C:  ' + str(issuer.C) + '\n')
					window.addstr('ST: ' + str(issuer.ST) + '\n')
					window.addstr('L:  ' + str(issuer.L) + '\n')
					window.addstr('O:  ' + str(issuer.O) + '\n')
					window.addstr('OU: ' + str(issuer.OU) + '\n')
					window.addstr('CN: ' + str(issuer.CN) + '\n')
					window.addstr('EA: ' + str(issuer.emailAddress) + '\n')

					window.addstr('\nValid: ' + str(valid) + '\n')
				except curses.error:
					pass
			else:
				# cert name width (or) valid width (or) subject longest line + issuer longest line
				if width-2 < len(self.certs[self.selected][0])+1 or width-2 < 34 or\
						width-2 < 4 + self.certs[self.selected][2] + 1 + 4 + self.certs[self.selected][3] + 1:
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

						msg = 'C:  ' + str(subject.C)
						msg2 = 'C:  ' + str(issuer.C)
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						msg = 'ST: ' + str(subject.ST)
						msg2 = 'ST: ' + str(issuer.ST)
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						msg = 'L:  ' + str(subject.L)
						msg2 = 'L:  ' + str(issuer.L)
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						msg = 'O:  ' + str(subject.O)
						msg2 = 'O:  ' + str(issuer.O)
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						msg = 'OU: ' + str(subject.OU)
						msg2 = 'OU: ' + str(issuer.OU)
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						msg = 'CN: ' + str(subject.CN)
						msg2 = 'CN: ' + str(issuer.CN)
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						msg = 'EA: ' + str(subject.emailAddress)
						msg2 = 'EA: ' + str(issuer.emailAddress)
						window.addstr(msg + ' '*(5 + self.certs[self.selected][2]-len(msg)) + msg2 + '\n')

						window.addstr('\nValid: ' + str(valid) + '\n');
					except curses.error:
						pass

		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and ((not self.show_cert and self.selected > -2) or (self.show_cert and self.selected > 0)):
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < len(self.certs)-1:
			self.selected = self.selected+1
		elif key == ord('\n'):
			if self.selected == -2:
				window.addstr(1, 0, ' '*(width-2))
				path = self.get_editable(1, 0, stdscr, window, self.certspath, curses.color_pair(1), True)
				if path == '' or path == self.certspath:
					return(True)
				self.certspath = path
				self.certspath_toedit = True
				self.get()
			elif self.selected == -1:
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
				self.show_cert = not self.show_cert
		elif key == curses.KEY_DC and self.selected > -1:
			self.certs_toremove.append(os.path.join(self.certspath, self.certs[self.selected][0]) + '.pem')
			del self.certs[self.selected]
			self.selected -= 1;
		elif key == curses.KEY_NPAGE and self.selected != len(self.certs)-1:
			if self.selected < 0:
				self.selected += height-3
			else:
				self.selected += height-2
			if self.selected > len(self.certs)-1:
				self.selected = len(self.certs)-1
		elif key == curses.KEY_PPAGE and self.selected != -2:
			self.selected -= height-2
			if self.selected < -2:
				self.selected = -2
		else:
			curses.flash()
		return(True)

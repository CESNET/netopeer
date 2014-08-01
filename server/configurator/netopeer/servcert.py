#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import M2Crypto
import nc_module
import messages
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

class servcert(nc_module.nc_module):
	name = 'Server Certificate'

	certpath = None
	stunnelpath = None
	stunnel_certpath = None
	stunnel_keypath = None
	crt = None
	pem = None
	key_toreplace = None
	crt_toreplace = None
	pem_toreplace = None

	def find(self):
		if os.path.exists(config.paths['cfgdir']):
			self.certpath = config.paths['cfgdir'] + '/stunnel'
			if not os.path.isdir(self.certpath):
				messages.append('stunnel directory does not exist, creating it', 'warning')
				if not os.mkdir(self.certspath, 0700):
					messages.append('stunnel directory could not be created', 'error')
					self.certspath = None
			self.stunnelpath = config.paths['cfgdir'] + '/stunnel_config'
			if not os.path.isfile(self.stunnelpath):
				messages.append('netopeer stunnel config file not found', 'error')
				self.stunnelpath = None
		else:
			messages.append('netopeer stunnel directory not found', 'error')
		return(True)

	def parse_cert(self, path):
		try:
			cert = M2Crypto.X509.load_cert(path)
		except (IOError, M2Crypto.X509.X509Error):
			cert = None
		if not cert:
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

		return((path[-3:].upper(), cert, subj_line_len, iss_line_len))

	def get_stunnel_config(self):
		if not self.stunnelpath:
			return((None, None))
		try:
			file = open(self.stunnelpath, 'r')
		except OSError:
			return((None, None))
		text = file.read()
		file.close()

		i = text.find('\ncert = ')
		if i == -1:
			messages.append('stunnel config file does not define any server certificate', 'error')
			return((None, None))
		i += 8
		certpath = text[i : text.find('\n', i)]

		i = text.find('\nkey = ')
		if i == -1:
			keypath = None
		else:
			i += 7
			keypath = text[i : text.find('\n', i)]

		return((certpath, keypath))

	def set_stunnel_config(self, certpath, keypath):
		if not self.stunnelpath or not certpath:
			return(None)
		try:
			conf = open(self.stunnelpath, 'r')
		except OSError:
			return(None)
		text = conf.read()
		conf.close()

		startcert = text.find('\ncert = ')
		if startcert == -1:
			messages.append('Corrupted stunnel config file: no certificate specified', 'error')
			return(None)
		startcert += 8;
		endcert = text.find('\n', startcert)

		startkey = text.find('\nkey = ')
		if keypath:
			if startkey == -1:
				startkey = text.find('\n;key = ')
				if startkey != -1:
					key_commented = True
			else:
				startkey += 6
				key_commented = False
		if startkey != -1:
			startkey += 1
			endkey = text.find('\n', startkey)

		try:
			conf = open(self.stunnelpath, 'w')
		except OSError:
			return(None)

		conf.write(text[:startcert])
		conf.write(certpath)
		if not keypath:
			if startkey == -1:
				conf.write(text[endcert:])
			else:
				conf.write(text[endcert:startkey])
				conf.write(';')
				conf.write(text[startkey:])
		else:
			if startkey == -1:
				conf.write('\nkey = ')
				conf.write(keypath)
				conf.write(text[endcert:])
			else:
				if key_commented:
					conf.write(text[endcert:startkey])
					conf.write('key = ')
					conf.write(keypath)
					conf.write(text[endkey:])
				else:
					conf.write(text[endcert:startkey])
					conf.write(keypath)
					conf.write(text[endkey:])

		conf.close()

	def get(self):
		if self.certpath:
			self.pem = None
			self.crt = None
			(self.stunnel_certpath, self.stunnel_keypath) = self.get_stunnel_config()
			if self.stunnel_certpath and not self.stunnel_keypath:
				self.pem = self.parse_cert(self.stunnel_certpath)
			elif self.stunnel_certpath and self.stunnel_keypath:
				self.crt = self.parse_cert(self.stunnel_certpath)
				if not os.path.isfile(self.stunnel_keypath):
					self.crt = None

		return(True)

	def update(self):
		if self.pem_toreplace:
			pempath = os.path.join(self.certpath, 'server.pem')
			if os.path.isfile(pempath):
				try:
					os.remove(pempath)
				except OSError as e:
					messages.append('Could not remove \"' + pempath + '\": ' + e.strerror + '\n', 'error')
			try:
				shutil.copyfile(self.pem_toreplace, pempath)
			except Error:
				messages.append('Could not copy \"' + self.pem_toreplace + '\": src and dest are the same', 'error')
				return(False)
			except IOError as e:
				messages.append('Could not copy \"' + self.pem_toreplace + '\": ' + e.strerror + '\n', 'error')
				return(False)

		if self.crt_toreplace and self.key_toreplace:
			crtpath = os.path.join(self.certpath, 'server.crt')
			if os.path.isfile(crtpath):
				try:
					os.remove(crtpath)
				except OSError as e:
					messages.append('Could not remove \"' + crtpath + '\": ' + e.strerror + '\n', 'error')
			try:
				shutil.copyfile(self.crt_toreplace, crtpath)
			except Error:
				messages.append('Could not copy \"' + self.crt_toreplace + '\": src and dest are the same', 'error')
				return(False)
			except IOError as e:
				messages.append('Could not copy \"' + self.crt_toreplace + '\": ' + e.strerror + '\n', 'error')
				return(False)

			keypath = os.path.join(self.certpath, 'server.key')
			if os.path.isfile(keypath):
				try:
					os.remove(keypath)
				except OSError as e:
					messages.append('Could not remove \"' + keypath + '\": ' + e.strerror + '\n', 'error')
			try:
				shutil.copyfile(self.key_toreplace, keypath)
			except Error:
				messages.append('Could not copy \"' + self.key_toreplace + '\": src and dest are the same', 'error')
				return(False)
			except IOError as e:
				messages.append('Could not copy \"' + self.key_toreplace + '\": ' + e.strerror + '\n', 'error')
				return(False)

		changes = False
		if self.pem_toreplace:
			self.set_stunnel_config(pempath, None)
			self.pem_toreplace = None
			changes = True
		elif self.crt_toreplace and self.key_toreplace:
			self.set_stunnel_config(crtpath, keypath)
			self.crt_toreplace = None
			self.key_toreplace = None
			changes = True

		if changes:
			stunnel_pidpath = config.paths['cfgdir'] + '/stunnel/stunnel.pid'
			if os.path.exists(stunnel_pidpath):
				try:
					pidfile = open(stunnel_pidpath, 'r')
					stunnelpid = int(pidfile.read())
					os.kill(stunnelpid, signal.SIGHUP)
				except (ValueError, IOError, OSError):
					messages.append('netopeer stunnel pid file found, but could not force config reload, changes may not take effect before stunnel restart', 'error')

		return self.get()

	def refresh(self, window, focus, height, width):
		return(True)

	def paint(self, window, focus, height, width):
		tools = [('INS', 'replace')]
		if not self.pem and not self.crt:
			if not self.stunnel_certpath and not self.stunnel_keypath:
				window.addstr('FAIL: Inaccessible or corrupted stunnel config file')
			if self.stunnel_certpath and not self.stunnel_keypath:
				window.addstr('FAIL: Inaccessible or corrupted certificate and key in:\n')
				window.addstr(self.stunnel_certpath, curses.color_pair(0) | curses.A_UNDERLINE)
			if self.stunnel_certpath and self.stunnel_keypath:
				window.addstr('FAIL: Inaccessible or corrupted certificate in:\n')
				window.addstr(self.stunnel_certpath, curses.color_pair(0) | curses.A_UNDERLINE)
			return(tools)

		if self.pem:
			window.addstr('Using the certificate and key in:\n')
			window.addstr(self.stunnel_certpath + '\n\n', curses.color_pair(0) | curses.A_UNDERLINE)
			subject = self.pem[1].get_subject()
			issuer = self.pem[1].get_issuer()
			valid = self.pem[1].get_not_after()
			subj_line_len = self.pem[2]
			iss_line_len = self.pem[3]

		if self.crt:
			window.addstr('Using the certificate in:\n')
			window.addstr(self.stunnel_certpath + '\n', curses.color_pair(0) | curses.A_UNDERLINE)
			window.addstr('With the private key in:\n')
			window.addstr(self.stunnel_keypath + '\n\n', curses.color_pair(0) | curses.A_UNDERLINE)
			subject = self.crt[1].get_subject()
			issuer = self.crt[1].get_issuer()
			valid = self.crt[1].get_not_after()
			subj_line_len = self.crt[2]
			iss_line_len = self.crt[3]

		if (self.pem and height > 23) or (self.crt and height > 24):
			try:
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
			try:
				msg = 'Subject'
				window.addstr(msg + ' '*(5 + subj_line_len-len(msg)) + 'Issuer\n')

				if subject.C:
					msg = 'C:  ' + subject.C
				else:
					msg = 'C:  None'
				if issuer.C:
					msg2 = 'C:  ' + issuer.C
				else:
					msg2 = 'C:  None'
				window.addstr(msg + ' '*(5 + subj_line_len-len(msg)) + msg2 + '\n')

				if subject.ST:
					msg = 'ST: ' + subject.ST
				else:
					msg = 'ST:  None'
				if issuer.ST:
					msg2 = 'ST: ' + issuer.ST
				else:
					msg2 = 'ST:  None'
				window.addstr(msg + ' '*(5 + subj_line_len-len(msg)) + msg2 + '\n')

				if subject.L:
					msg = 'L:  ' + subject.L
				else:
					msg = 'L:  None'
				if issuer.L:
					msg2 = 'L:  ' + issuer.L
				else:
					msg2 = 'L:  None'
				window.addstr(msg + ' '*(5 + subj_line_len-len(msg)) + msg2 + '\n')

				if subject.O:
					msg = 'O:  ' + subject.O
				else:
					msg = 'O:  None'
				if issuer.O:
					msg2 = 'O:  ' + issuer.O
				else:
					msg2 = 'O:  None'
				window.addstr(msg + ' '*(5 + subj_line_len-len(msg)) + msg2 + '\n')

				if subject.OU:
					msg = 'OU: ' + subject.OU
				else:
					msg = 'OU: None'
				if issuer.OU:
					msg2 = 'OU: ' + issuer.OU
				else:
					msg2 = 'OU: None'
				window.addstr(msg + ' '*(5 + subj_line_len-len(msg)) + msg2 + '\n')

				if subject.CN:
					msg = 'CN: ' + subject.CN
				else:
					msg = 'CN: None'
				if issuer.CN:
					msg2 = 'CN: ' + issuer.CN
				else:
					msg2 = 'CN: None'
				window.addstr(msg + ' '*(5 + subj_line_len-len(msg)) + msg2 + '\n')

				if subject.emailAddress:
					msg = 'EA: ' + subject.emailAddress
				else:
					msg = 'EA: None'
				if issuer.emailAddress:
					msg2 = 'EA: ' + issuer.emailAddress
				else:
					msg2 = 'EA: None'
				window.addstr(msg + ' '*(5 + subj_line_len-len(msg)) + msg2 + '\n')

				window.addstr('\nValid: ' + str(valid) + '\n')
			except curses.error:
				pass

		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_IC:
			selected = 0
			while True:
				try:
					window.erase()
					window.addstr('Single file (PEM)\n', curses.color_pair(0) | curses.A_REVERSE if selected == 0 else 0)
					window.addstr('Two files (CRT and KEY)', curses.color_pair(0) | curses.A_REVERSE if selected == 1 else 0)
					window.refresh()
				except curses.error:
					pass

				key = stdscr.getch()
				if key == ord('\n'):
					break
				elif key == curses.KEY_DOWN and selected == 0:
					selected = 1
				elif key == curses.KEY_UP and selected == 1:
					selected = 0
				elif key == curses.KEY_LEFT:
					return(True)
				else:
					curses.flash()

			window.erase()
			certpath = None
			keypath = None
			if selected == 0:
				window.addstr('PEM absolute path: ')
				certpath = self.get_editable(0, 19, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
				if certpath == '':
					return(True)
				pem = self.parse_cert(certpath)
				if not pem:
					messages.append('Certificate \"' + certpath + '\" inaccessible or not valid', 'error')
					return(True)

				self.stunnel_certpath = certpath
				self.stunnel_keypath = None
				self.crt = None
				self.pem = pem

				self.pem_toreplace = certpath
			else:
				window.addstr('CRT absolute path: ')
				certpath = self.get_editable(0, 19, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
				if certpath == '':
					return(True)
				crt = self.parse_cert(certpath)
				if not crt:
					messages.append('Certificate \"' + certpath + '\" inaccessible or not valid', 'error')
					return(True)

				window.erase()
				window.addstr('KEY absolute path: ')
				keypath = self.get_editable(0, 19, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
				if keypath == '':
					return(True)
				if not os.path.isfile(keypath):
					messages.append('Private key \"' + keypath + '\" inaccessible', 'error')
					return(True)

				self.stunnel_certpath = certpath
				self.stunnel_keypath = keypath
				self.crt = crt
				self.pem = None

				self.crt_toreplace = certpath
				self.key_toreplace = keypath
		else:
			curses.flash()
		return(True)

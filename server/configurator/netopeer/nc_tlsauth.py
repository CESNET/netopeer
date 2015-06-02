#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import M2Crypto
import ncmodule
import libxml2
import string
import messages
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

class nc_tlsauth(ncmodule.ncmodule):
	name = 'TLS Authentication'

	netopeer_path = None
	netopeer_doc = None
	netopeer_ctxt = None

	server_cert = None
	server_cert_change = False
	server_key = None
	server_key_type = None
	server_key_change = False
	ca_certs = []
	ca_certs_change = False

	show_cert = False
	linewidth = 18

	# curses
	selected = -3

	def find(self):
		libxml2.keepBlanksDefault(0)

		if not os.path.exists(config.paths['modulesdir']):
			messages.append('Netopeer modules directory not found.', 'error')
			return False

		module_path = os.path.join(config.paths['modulesdir'], 'Netopeer.xml')
		if not os.path.isfile(module_path):
			messages_append('Netopeer module configuration not found', 'error')
			return False

		module_doc = libxml2.parseFile(module_path)
		module_ctxt = module_doc.xpathNewContext()

		xpath_repo_type = module_ctxt.xpathEval('/device/repo/type')
		if not xpath_repo_type:
			messages.append('Module Netopeer is not valid, repo type is not specified', 'error')
			return False
		elif len(xpath_repo_type) != 1:
			messages.append('Module Netopeer is not valid, there are multiple repo types specified', 'error')
			return False
		elif xpath_repo_type[0].get_content() != 'file':
			messages.append('Module Netopeer is not valid, the repository is not a file', 'error')
			return False

		xpath_repo_path = module_ctxt.xpathEval('/device/repo/path')
		if not xpath_repo_path:
			messages.append('Module Netopeer is not valid, repo path is not specified', 'error')
			return False
		elif len(xpath_repo_path) != 1:
			messages.append('Module Netopeer is not valid, there are multiple repo paths specified', 'error')
			return False
		self.netopeer_path = xpath_repo_path[0].get_content()

		return True

	def parse_cert(self, der_cert_or_path):
		try:
			if len(der_cert_or_path) > 256:
				cert = M2Crypto.X509.load_cert_string('-----BEGIN CERTIFICATE-----\n'+der_cert_or_path+'\n-----END CERTIFICATE-----')
			else:
				cert = M2Crypto.X509.load_cert(der_cert_or_path)
		except (IOError, M2Crypto.X509.X509Error):
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

		return (cert, subj_line_len, iss_line_len)

	def get(self):
		if self.netopeer_path:
			if not os.path.exists(self.netopeer_path) or os.path.getsize(self.netopeer_path) == 0:
				datastore = open(self.netopeer_path, 'w')
				datastore.write('<?xml version="1.0" encoding="UTF-8"?>\n<datastores xmlns="urn:cesnet:tmc:datastores:file">\n  <running lock=""/>\n  <startup lock=""/>\n  <candidate modified="false" lock=""/>\n</datastores>')
				datastore.close()

			self.netopeer_doc = libxml2.parseFile(self.netopeer_path)
			self.netopeer_ctxt = self.netopeer_doc.xpathNewContext()
			self.netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
			self.netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')

			# server certificate
			self.server_cert = None
			server_cert_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:server-cert')
			if len(server_cert_nodes) > 0:
				if len(server_cert_nodes) > 1:
					messages.append('More "server-cert" nodes found, using the first', 'warning')
				server_cert_node = server_cert_nodes[0]
				cert = self.parse_cert(server_cert_node.content)
				if cert == None:
					messages.append('Could not parse the server certificate', 'warning')
				else:
					self.server_cert = cert

			# server key
			self.server_key = None
			self.server_key_type = None
			server_key_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:server-key')
			if len(server_key_nodes) > 0:
				if len(server_key_nodes) > 1:
					messages.append('More "server-key" nodes found, using the first', 'warning')
				server_key_data_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:server-key/n:key-data')
				server_key_type_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:server-key/n:key-type')
				if len(server_key_data_nodes) > 0 or len(server_key_type_nodes) > 0:

					key_error = False
					if len(server_key_data_nodes) == 0:
						messages.append('"key-data" node is missing', 'warning')
						key_error = True
					if len(server_key_type_nodes) == 0:
						messages.append('"key-type" node is missing', 'warning')
						key_error = True

					if not key_error:
						if len(server_key_data_nodes) > 1:
							messages.append('More "key-data" nodes found, using the first', 'warning')
						if len(server_key_type_nodes) > 1:
							messages.append('More "key-type" nodes found, using the first', 'warning')

						key_type = server_key_type_nodes[0].content
						if key_type != 'RSA' and key_type != 'DSA':
							messages.append('"key-type" is unsupported (' + key_type + ')', 'warning')
						else:
							try:
								if key_type == 'RSA':
									key = M2Crypto.RSA.load_key_string('-----BEGIN RSA PRIVATE KEY-----\n' + server_key_data_nodes[0].content + '\n-----END RSA PRIVATE KEY-----')
								else:
									key_bio = M2Crypto.BIO.MemoryBuffer('-----BEGIN DSA PRIVATE KEY-----\n' + server_key_data_nodes[0].content + '\n-----END DSA PRIVATE KEY-----')
									key = M2Crypto.DSA.load_key_bio(key_bio)
							except (M2Crypto.RSA.RSAError, M2Crypto.DSA.DSAError):
								key = None
							if key == None:
								messages.append('Could not parse the server private key', 'error')
							else:
								self.server_key = key
								self.server_key_type = key_type

			# trusted CA certs
			self.ca_certs = []
			ca_cert_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:trusted-ca-certs/n:trusted-ca-cert')
			for ca_cert_node in ca_cert_nodes:
				cert = self.parse_cert(ca_cert_node.content)
				if cert == None:
					messages.append('Could not parse a CA certificate', 'warning')
					continue
				self.ca_certs.append(cert)
				self.ca_certs.sort()

		return True

	def update(self):
		# so that we have the current datastore content, otherwise the changes would be lost
		self.netopeer_doc = libxml2.parseFile(self.netopeer_path)
		self.netopeer_ctxt = self.netopeer_doc.xpathNewContext()
		self.netopeer_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
		self.netopeer_ctxt.xpathRegisterNs('n', 'urn:cesnet:tmc:netopeer:1.0')

		# create the tls container if not exists
		tls_node = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls')
		if len(tls_node) == 0:
			netopeer_node = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer')
			tls_node = netopeer_node[0].newChild(netopeer_node[0].ns(), 'tls', None)
		else:
			tls_node = tls_node[0]

		# server cert
		if self.server_cert_change:
			server_cert_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:server-cert')
			if len(server_cert_nodes) == 0:
				server_cert_node = tls_node.newChild(tls_node.ns(), 'server-cert', None)
			else:
				server_cert_node = server_cert_nodes[0]

			if self.server_cert == None:
				server_cert_node.unlinkNode()
			else:
				server_cert_node.setContent(self.server_cert[0].as_pem()[28:-27])

			self.server_cert_change = False

		# server key
		if self.server_key_change:
			server_key_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:server-key')
			if len(server_key_nodes) == 0:
				server_key_node = tls_node.newChild(tls_node.ns(), 'server-key', None)
			else:
				server_key_node = server_key_nodes[0]

			server_key_data_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:server-key/n:key-data')
			if len(server_key_data_nodes) == 0:
				server_key_data_node = server_key_node.newChild(server_key_node.ns(), 'key-data', None)
			else:
				server_key_data_node = server_key_data_nodes[0]

			if self.server_key == None:
				server_key_data_node.unlinkNode()
			elif self.server_key_type == 'RSA':
				server_key_data_node.setContent(self.server_key.as_pem(cipher=None)[32:-31])
			else:
				key_bio = M2Crypto.BIO.MemoryBuffer()
				self.server_key.save_key_bio(key_bio, cipher=None)
				server_key_data_node.setContent(key_bio.read_all()[32:-31])

			server_key_type_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:server-key/n:key-type')
			if len(server_key_type_nodes) == 0:
				server_key_type_node = server_key_node.newChild(server_key_node.ns(), 'key-type', None)
			else:
				server_key_type_node = server_key_type_nodes[0]

			if self.server_key_type == None:
				server_key_type_node.unlinkNode()
			else:
				server_key_type_node.setContent(self.server_key_type)

			self.server_key_change = False

		# trusted CA certs
		if self.ca_certs_change:
			trusted_ca_certs_nodes = self.netopeer_ctxt.xpathEval('/d:datastores/d:startup/n:netopeer/n:tls/n:trusted-ca-certs')
			if len(trusted_ca_certs_nodes) > 0:
				trusted_ca_certs_nodes[0].unlinkNode()
			trusted_ca_certs_node = tls_node.newChild(tls_node.ns(), 'trusted-ca-certs', None)

			for ca_cert in self.ca_certs:
				trusted_ca_certs_node.newChild(trusted_ca_certs_node.ns(), 'trusted-ca-cert', ca_cert[0].as_pem()[28:-27])

			self.ca_certs_change = False

		self.netopeer_doc.saveFormatFile(self.netopeer_path, 1)
		return True

	def unsaved_changes(self):
		if self.server_cert_change or self.server_key_change or self.ca_certs_change:
			return True

		return False

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
		tools = []
		if not self.show_cert:
			if self.selected == -3 or self.selected == -2:
				if self.selected == -3:
					tools.append(('ENTER', 'show'))
				if (self.selected == -3 and self.server_cert != None) or (self.selected == -2 and self.server_key != None):
					tools.append(('DEL', 'remove'))
				tools.append(('INS', 'replace'))
			elif self.selected == -1:
				tools.append(('ENTER', 'add cert'))
			else:
				tools.append(('ENTER', 'show'))
				tools.append(('DEL', 'remove'))

			tools.append(('PGUP, PGDOWN', 'scrolling'))

			if self.selected < height-8:
				cert_index = 0
			else:
				cert_index = ((self.selected+6) / (height-2)) * (height-2) - 6

			if cert_index == 0:
				cert_count = height-7;
				if self.server_cert == None:
					if 28 > self.linewidth:
						self.linewidth = 28
					self.maddstrln(window, width, 'Server certificate (not set)'+' '*(self.linewidth-28), curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == -3 else 0)
				else:
					self.maddstrln(window, width, 'Server certificate'+' '*(self.linewidth-18), curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == -3 else 0)
				if self.server_key == None:
					if 20 > self.linewidth:
						self.linewidth = 20
					self.maddstrln(window, width, 'Server key (not set)'+' '*(self.linewidth-20), curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == -2 else 0)
				else:
					self.maddstrln(window, width, 'Server key ('+self.server_key_type+')'+' '*((self.linewidth-13)-len(self.server_key_type)), curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == -2 else 0)
				self.maddstrln(window, width, '')
				self.maddstrln(window, width, 'Trusted CA certificates:')
				self.maddstrln(window, width, 'Add a certificate', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == -1 else 0, self.linewidth)
				self.maddstrln(window, width, '')
			else:
				cert_count = height-2;

			try:
				i = 0
				while cert_index+i < len(self.ca_certs) and i < cert_count:
					self.maddstrln(window, width, 'CA cert {d}'.format(d=cert_index+i), curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == cert_index+i else 0, self.linewidth)
					i += 1
				if len(self.ca_certs) == 0:
					self.maddstrln(window, width, 'None')
			except curses.error:
				pass
		else:
			tools.append(('ENTER', 'hide'))
			tools.append(('DEL', 'remove'))

			if self.selected == -3:
				cert = self.server_cert[0]
			else:
				cert = self.ca_certs[self.selected][0]
			subject = cert.get_subject()
			issuer = cert.get_issuer()
			valid = cert.get_not_after()

			if height > 22:
				try:
					if self.selected == -3:
						window.addstr('Server cert\n\n')
					else:
						window.addstr('CA cert {d}\n\n'.format(d=self.selected))
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
				sub_len = self.server_cert[1] if self.selected == -3 else self.ca_certs[self.selected][1]
				iss_len = self.server_cert[2] if self.selected == -3 else self.ca_certs[self.selected][2]

				if width-2 < 34 or width-2 < 4 + sub_len + 1 + 4 + iss_len + 1:
					self.show_cert = False
					tools.pop()
					tools.append(('ENTER', 'show'))
					messages.append('Cannot show cert, terminal too small', 'warning')
					self.paint(window, focus, height, width)
				else:
					try:
						if self.selected == -3:
							window.addstr('Server cert\n\n')
						else:
							window.addstr('CA cert {d}\n\n'.format(d=self.selected))
						msg = 'Subject'
						window.addstr(msg + ' '*(5 + sub_len-len(msg)) + 'Issuer\n')

						msg = 'C:  ' + str(subject.C)
						msg2 = 'C:  ' + str(issuer.C)
						window.addstr(msg + ' '*(5 + sub_len-len(msg)) + msg2 + '\n')

						msg = 'ST: ' + str(subject.ST)
						msg2 = 'ST: ' + str(issuer.ST)
						window.addstr(msg + ' '*(5 + sub_len-len(msg)) + msg2 + '\n')

						msg = 'L:  ' + str(subject.L)
						msg2 = 'L:  ' + str(issuer.L)
						window.addstr(msg + ' '*(5 + sub_len-len(msg)) + msg2 + '\n')

						msg = 'O:  ' + str(subject.O)
						msg2 = 'O:  ' + str(issuer.O)
						window.addstr(msg + ' '*(5 + sub_len-len(msg)) + msg2 + '\n')

						msg = 'OU: ' + str(subject.OU)
						msg2 = 'OU: ' + str(issuer.OU)
						window.addstr(msg + ' '*(5 + sub_len-len(msg)) + msg2 + '\n')

						msg = 'CN: ' + str(subject.CN)
						msg2 = 'CN: ' + str(issuer.CN)
						window.addstr(msg + ' '*(5 + sub_len-len(msg)) + msg2 + '\n')

						msg = 'EA: ' + str(subject.emailAddress)
						msg2 = 'EA: ' + str(issuer.emailAddress)
						window.addstr(msg + ' '*(5 + sub_len-len(msg)) + msg2 + '\n')

						window.addstr('\nValid: ' + str(valid) + '\n');
					except curses.error:
						pass

		return tools

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and ((not self.show_cert and self.selected > -3) or (self.show_cert and self.selected > 0)):
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < len(self.ca_certs)-1 and (not self.show_cert or self.selected > -1):
			self.selected = self.selected+1
		elif key == ord('\n'):
			if self.selected == -1:
				window.addstr(4, 0, 'Absolute path: '+' '*(self.linewidth-15))
				path = self.get_editable(4, 15, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
				if path == '':
					return True
				try:
					cert = self.parse_cert(path)
				except (IOError, M2Crypto.X509.X509Error):
					cert = None

				if cert == None:
					messages.append('\"' + path + '\" is not a valid certificate', 'error')
					return True

				if not cert[0].check_ca():
					messages.append('Certificate \"' + os.path.basename(path) + '\" not a CA certificate', 'error')
					return True

				for old_cert in self.ca_certs:
					if cert[0].get_fingerprint() == old_cert[0].get_fingerprint():
						messages.append('Certificate \"' + os.path.basename(path) + '\" already trusted', 'error')
						return True

				self.ca_certs.append(cert)
				self.ca_certs.sort()
				self.ca_certs_change = True
			elif (self.selected == -3 and self.server_cert != None) or self.selected > -1:
				self.show_cert = not self.show_cert
			else:
				curses.flash()

		elif key == curses.KEY_DC:
			if self.selected == -3 and self.server_cert != None:
				self.server_cert = None
				self.server_cert_change = True
				if self.show_cert:
					self.show_cert = False
			elif self.selected == -2 and self.server_key != None:
				self.server_key = None
				self.server_key_type = None
				self.server_key_change = True
			elif self.selected > -1:
				del self.ca_certs[self.selected]
				self.ca_certs_change = True
				self.selected -= 1;
				if self.show_cert and self.selected == -1:
					self.show_cert = False
			else:
				curses.flash()

		elif key == curses.KEY_IC and self.selected < -1 and not self.show_cert:
			if self.selected == -3:
				window.addstr(0, 0, 'Absolute path: '+' '*(self.linewidth-15))
				path = self.get_editable(0, 15, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
				if path == '':
					return True
				try:
					cert = self.parse_cert(path)
				except (IOError, M2Crypto.X509.X509Error):
					cert = None

				if cert == None:
					messages.append('"' + path + '" is not a valid certificate', 'error')
					return True

				if cert[0].check_ca():
					messages.append('Certificate \"' + os.path.basename(path) + '\" is a CA certificate', 'error')
					return True

				self.server_cert = cert
				self.server_cert_change = True

			elif self.selected == -2:
				window.addstr(1, 0, 'Absolute path: '+' '*(self.linewidth-15))
				path = self.get_editable(1, 15, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE, True)
				if path == '':
					return True

				key_type = None
				try:
					key_file = open(path, 'r')
				except IOError as e:
					messages.append('File "' + path + '" open: ' + e.strerror, 'error')
					return True
				key_data = key_file.read()
				key_file.close()
				if string.find(key_data, '-----BEGIN RSA PRIVATE KEY-----\n') > -1:
					key_type = 'RSA'
				elif string.find(key_data, '-----BEGIN DSA PRIVATE KEY-----\n') > -1:
					key_type = 'DSA'
				else:
					messages.append('"' + path + '" is in an unknown format', 'error')
					return True

				try:
					if key_type == 'RSA':
						key = M2Crypto.RSA.load_key(path)
					else:
						key = M2Crypto.DSA.load_key(path)
				except (M2Crypto.RSA.RSAError, M2Crypto.DSA.DSAError):
					key = None
				if key == None:
					messages.append('"' + path + '" is not a valid private key', 'error')

				self.server_key = key
				self.server_key_type = key_type
				self.server_key_change = True

		elif key == curses.KEY_NPAGE and not self.show_cert and self.selected != len(self.ca_certs)-1:
			if self.selected == -3 or self.selected == -2:
				self.selected += height-5
			elif self.selected == -1:
				self.selected += height-3
			else:
				self.selected += height-2

			if self.selected > len(self.ca_certs)-1:
				self.selected = len(self.ca_certs)-1

		elif key == curses.KEY_PPAGE and not self.show_cert and self.selected != -3:
			if self.selected == height-8 or self.selected == height-7:
				self.selected -= height-5
			elif self.selected == height-6:
				self.selected = -2
			elif self.selected == height-4 or self.selected == height-5:
				self.selected = -1
			else:
				self.selected -= height-2

			if self.selected < -3:
				self.selected = -3

		else:
			curses.flash()

		return True

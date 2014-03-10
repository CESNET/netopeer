#!/usr/bin/python
# -*- coding:utf-8 -*-

import nc_module
import messages
import os
import re
import subprocess
import curses

class sshd(nc_module.nc_module):
	name = 'SSH daemon'
	# configuration file path
	binary_path = None
	config_path = None
	# sshd ports
	ports = []
	# agent path
	agent = None
	# curses
	selected = 0

	def find(self):
		"""Try to find sshd binary and parse configuration location from its debug output."""

		# find sshd binary in PATH if not specified
		if not self.binary_path:
			for path in os.environ['PATH'].split(os.pathsep):
				if os.path.exists(os.path.join(path, 'sshd')) and os.access(os.path.join(path, 'sshd'), os.X_OK):
					self.binary_path = os.path.join(path, 'sshd')
					break

		if self.binary_path:
			sshd_output = subprocess.check_output('{s} -d -d -t'.format(s=self.binary_path), stderr=subprocess.STDOUT, shell=True).split(os.linesep)
			for line in sshd_output:
				config = re.match(r'.*load_server_config:\s*filename\s*(.*)', line)
				if config is not None:
					self.config_path = config.group(1).strip()
					break

		if self.config_path and len(self.config_path) > 0:
			return(True)
		elif os.path.exists('/etc/ssh/sshd_config'):
			self.config_path = '/etc/ssh/sshd_config'
			return(True)
		else:
			messages.append('Failed to find SSH daemon configuration file. Ports and subsystem can not be configured.')
			self.config_path = None
			return(False)

	def get(self):
		subsystems = []
		if self.config_path:
			for line in open(self.config_path):
				port = re.match(r'Port\s(\d*)', line)
				subsystem = re.match(r'Subsystem\s*netconf\s*(.*)', line)
				if port:
					port_int = int(port.group(1).strip())
					if not port_int in self.ports:
						self.ports.append(port_int)
				elif subsystem:
					subsystems.append(subsystem.group(1).strip())

			self.agent = subsystems[0] if subsystems else None

		if not self.agent:
			for module in self.all_modules:
				if module.name == 'Netopeer':
					self.agent = module.agent_path

		return(True)

	def update(self):
		if not self.config_path:
			messages.append('Cannot write changes. Path to SSH daemon config is not specified.')
			return(False)
		else:
			try:
				sshd_file = open(self.config_path, 'r')
				sshd_lines = sshd_file.readlines()
				sshd_file.close()
			except IOError:
				sshd_lines = []

			# remove all Ports and netconf Subsystems
			for line in sshd_lines:
				if re.match(r'Port\s\d*', line) or re.match(r'Subsystem\s*netconf\s*.*', line):
					sshd_lines.remove(line)

			# add configured ports and subsystem if cofigured
			if self.ports:
				ports_done = False
			else:
				ports_done = True
			if self.agent:
				subsystem_done = False
			else:
				subsystem_done = True

			for line in sshd_lines:
				if (not ports_done) and re.match(r'#\s*Port', line):
					ports_done = True
					for port in self.ports:
						sshd_lines.insert(sshd_lines.index(line)+1, 'Port {d}\n'.format(d=port))
				elif (not subsystem_done) and re.match(r'#?\s*Subsystem', line):
					subsystem_done = True
					sshd_lines.insert(sshd_lines.index(line)+1, 'Subsystem netconf {s}\n'.format(s=self.agent))

			if not ports_done:
				for port in self.ports:
					sshd_lines.append('Port {d}\n'.format(d=port))
			if not subsystem_done:
				sshd_lines.append('Subsystem netconf {s}\n'.format(s=self.agent))

			sshd_file = open(self.config_path, 'w')
			sshd_file.writelines(sshd_lines)
			sshd_file.close()
			return(True)

	def paint(self, window, focus, height, width):
		tools = []
		window.addstr('Using SSH daemon configuration in file:\n')
		if focus and self.selected == 0:
			window.addstr('{s}\n'.format(s=self.config_path), curses.color_pair(1))
			tools.append(('e','edit'))
		else:
			window.addstr('{s}\n'.format(s=self.config_path), curses.color_pair(2))
		window.addstr('\n')

		window.addstr('As netconf subsystem will used:\n')
		if focus and self.selected == 1:
			window.addstr('{s}\n'.format(s=self.agent), curses.color_pair(1))
			tools.append(('e','edit'))
		else:
			window.addstr('{s}\n'.format(s=self.agent), curses.color_pair(2))
		window.addstr('\n')

		if self.ports:
			if focus and self.selected == 2:
				window.addstr('Curently there are these port configured to be used by SSH daemon:\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Curently there are these port configured to be used by SSH daemon:\n', curses.color_pair(2))
			for port in self.ports:
				if focus and (self.ports.index(port)+3) == self.selected:
					window.addstr('{d}\n'.format(d=port), curses.color_pair(1))
					tools.append(('a','add'))
					tools.append(('d','delete'))
					tools.append(('e','edit'))
				else:
					window.addstr('{d}\n'.format(d=port), curses.color_pair(2))
		else:
			if focus and self.selected == 2:
				window.addstr('There are no configured ports for SSH daemon. The default one (22) will be used.', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('There are no configured ports for SSH daemon. The default one (22) will be used.', curses.color_pair(2))
		return(tools)


	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < (len(self.ports)+2):
			self.selected = self.selected+1
		elif key == ord('e') and self.selected == 0:
			# edit ssh config path
			tmp_ssh_var = self.get_editable(1,0, stdscr, window, self.config_path, curses.color_pair(1))
			if tmp_ssh_var:
				if os.path.exists(tmp_ssh_var):
					self.config_path = tmp_ssh_var
					self.get()
				else:
					messages.append('\'{s}\' is not valid file.'.format(s=tmp_ssh_var))
		elif key == ord('e') and self.selected == 1:
			tmp_ssh_var = self.get_editable(4,0, stdscr, window, self.agent, curses.color_pair(1))
			if tmp_ssh_var:
				if os.path.exists(tmp_ssh_var):
					self.agent = tmp_ssh_var
				else:
					messages.append('\'{s}\' is not valid file.'.format(s=tmp_ssh_var))
		elif key == ord('e') and self.selected > 2:
			# edit port
			tmp_ssh_var = self.get_editable(self.selected+4,0, stdscr, window, str(self.ports[self.selected-3]), curses.color_pair(1))
			if tmp_ssh_var and tmp_ssh_var.isdigit() and int(tmp_ssh_var) in range(1,2**16):
				if int(tmp_ssh_var) in self.ports:
					messages.append('Port {d} already is in the list of configured ports.'.format(d=tmp_ssh_var))
				else:
					self.ports[self.selected-3] = int(tmp_ssh_var)
			else:
				messages.append('{d} is not valid port number.'.format(d=tmp_ssh_var))
		elif key == ord('a') and self.selected > 1:
			# add new port
			tmp_ssh_var = self.get_editable(len(self.ports)+7,0, stdscr, window, '', curses.color_pair(1))
			if tmp_ssh_var and tmp_ssh_var.isdigit() and int(tmp_ssh_var) in range(1,2**16):
				if int(tmp_ssh_var) in self.ports:
					messages.append('Port {d} already is in the list of configured ports.'.format(d=tmp_ssh_var))
				else:
					self.ports.append(int(tmp_ssh_var))
			else:
				messages.append('{d} is not valid port number.'.format(d=tmp_ssh_var))

		elif key == ord('d') and self.selected > 2:
			self.ports.remove(self.ports[self.selected-3])
			if self.selected > len(self.ports)+1:
				self.selected = self.selected-1
		else:
			curses.flash()
		return(True)

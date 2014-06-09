#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import libxml2
import subprocess
import nc_module
import messages

class acm:
	class action:
		DENY = 0
		PERMIT = 1

	class rule_type:
		OPERATION = 0
		NOTIFICATION = 1
		DATA = 2

	class operation:
		CREATE = 0
		READ = 1
		UPDATE = 2
		DELETE = 3
		EXEC = 4

class nacm_rule:
	name = ''
	module = ''
	type = None
	identificator = None
	operations = []
	action = None
	comment = ''

	def __init__(self,name):
		self.name = name

class nacm_rule_list:
	name = ''
	groups = []
	rules = []

	def __init__(self, name):
		self.name = name

class nacm_group:
	name = ''
	users = []

	def __init__(self, name, users):
		self.name = name
		self.users = users

class nacm(nc_module.nc_module):
	name = 'NACM'
	datastore_path = None
	enabled = True
	external_groups = True
	r_default = acm.action.PERMIT
	w_default = acm.action.DENY
	x_default = acm.action.PERMIT

	groups = []
	rule_lists = []
	almighty_users = []
	almighty_groups = []

	# curses
	selected = 0

	def find(self):
		"""Try to find NACM datastore."""
		try:
			ncworkingdir = subprocess.check_output('pkg-config libnetconf --variable=ncworkingdir', shell=True).split(os.linesep)[0]
		except:
			return(False)

		try:
			os.makedirs(ncworkingdir)
		except OSError as e:
			if e.errno == 17:
				# File exists
				pass
			else:
				# permission denied or filesystem error
				return(False)
		except:
			return(False)

		if not os.access(os.path.join(ncworkingdir, 'datastore-acm.xml'), os.W_OK):
			try:
				open(os.path.join(ncworkingdir, 'datastore-acm.xml'), 'w').close()
			except:
				return(False)

		self.datastore_path = os.path.join(ncworkingdir, 'datastore-acm.xml')
		return(True)

	def get(self):
		if not self.datastore_path:
			messages.append('Path to NACM datastore not specified.')
			return(False)

		try:
			nacm_doc = libxml2.readFile(self.datastore_path, None, libxml2.XML_PARSE_NOERROR|libxml2.XML_PARSE_NOWARNING)
		except:
			messages.append('Can not parse Access Control configuration. File %s is probably corrupted.' % self.datastore_path)
			return(True)

		nacm_ctxt = nacm_doc.xpathNewContext()
		nacm_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
		nacm_ctxt.xpathRegisterNs('n', 'urn:ietf:params:xml:ns:yang:ietf-netconf-acm')

		nacm_enable = nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:enable-nacm')
		nacm_external = nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:enable-external-groups')
		nacm_read_default = nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:read-default')
		nacm_write_default = nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:write-default')
		nacm_exec_default = nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:exec-default')

		nacm_group_names = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:groups/n:group/n:name'))

		nacm_rule_lists = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list/n:name'))

		if nacm_enable and nacm_enable[0].get_content() == 'false':
			self.enabled = False
		else:
			self.enabled = True

		if nacm_external and nacm_external[0].get_content == 'false':
			self.external_groups = False
		else:
			self.external_groups = True

		if nacm_read_default and nacm_read_default[0].get_content() == 'deny':
			self.r_default = acm.action.DENY
		else:
			self.r_default = acm.action.PERMIT

		if nacm_write_default and nacm_write_default[0].get_content() == 'permit':
			self.w_default = acm.action.PERMIT
		else:
			self.w_default = acm.action.DENY

		if nacm_exec_default and nacm_exec_default[0] and nacm_exec_default[0].get_content() == 'deny':
			self.x_default = acm.action.DENY
		else:
			self.x_default = acm.action.PERMIT

		for group_name in nacm_group_names:
			group_users = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:groups/n:group[n:name=\'{s}\']/n:user-name'.format(s=group_name)))
			self.groups.append(nacm_group(group_name, group_users))

		for rule_list_name in nacm_rule_lists:
			rule_list = nacm_rule_list(rule_list_name)

			rule_list.groups = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{s}\']/n:group'.format(s=rule_list_name)))
			if '*' in rule_list.groups:
				rule_list.groups = ['*']

			rule_names = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{s}\']/n:rule/n:name'.format(s=rule_list_name)))
			for rule_name in rule_names:
				rule = nacm_rule(rule_name)

				module_name = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[\'{rule}\']/n:module-name'.format(list=rule_list_name,rule=rule_name)))
				rpc_name = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[\'{rule}\']/n:protocol-operation/n:rpc-name'.format(list=rule_list_name,rule=rule_name)))
				notification_name = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[\'{rule}\']/n:notification/n:notification-name'.format(list=rule_list_name,rule=rule_name)))
				data_path = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[\'{rule}\']/n:data-node/n:path'.format(list=rule_list_name,rule=rule_name)))
				access_operation = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[\'{rule}\']/n:access-operation'.format(list=rule_list_name,rule=rule_name)))
				action = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[\'{rule}\']/n:action'.format(list=rule_list_name,rule=rule_name)))
				comment = map(libxml2.xmlNode.get_content, nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[\'{rule}\']/n:comment'.format(list=rule_list_name,rule=rule_name)))

				if module_name:
					rule.module = module_name[0]
				else:
					rule.module= '*'

				if rpc_name:
					rule.type = acm.rule_type.OPERATION
					rule.identificator = rpc_name[0]
				elif notification_name:
					rule.type = acm.rule_type.NOTIFICATION
					rule.identificator = notification_name[0]
				elif data_path:
					rule.type = acm.rule_type.DATA
					rule.identificator = data_path[0]

				if access_operation:
					if 'create' in access_operation[0].split():
						rule.operations.append(acm.operation.CREATE)
					if 'read' in access_operation[0].split():
						rule.operations.append(acm.operation.READ)
					if 'update' in access_operation[0].split():
						rule.operations.append(acm.operation.UPDATE)
					if 'delete' in access_operation[0].split():
						rule.operations.append(acm.operation.DELETE)
					if 'exec' in access_operation[0].split():
						rule.operations.append(acm.operation.EXEC)
					if '*' in access_operation[0].split():
						rule.operations = ['*']
				else:
					rule.operations = ['*']

				if action and action[0] == 'allow':
					rule.action = acm.action.PERMIT
				elif action and action[0] == 'deny':
					rule.action = acm.action.DENY
				else:
					messages.append('Missing mandatory element \'action\' in rule \'{s}\'. The rule will be skipped.'.format(s=rule_name))
					continue

				if comment:
					rule.comment = comment[0]

				rule_list.rules.append(rule)

			self.rule_lists.append(rule_list)

		return(True)

	def update(self):
		if not self.datastore_path:
			messages.append('Path to NACM datastore not specified.')
			return(False)

		nacm_doc = libxml2.newDoc('1.0')
		datastore_root = nacm_doc.newChild(None, 'datastores', None)
		datastore_root.newNs('urn:cesnet:tmc:datastores:file', None)
		startup = datastore_root.newChild(None, 'startup', None)
		nacm_root = startup.newChild(None, 'nacm', None)
		nacm_root.newNs('urn:ietf:params:xml:ns:yang:ietf-netconf-acm', None)
		if self.enabled:
			nacm_root.newChild(None, 'enable-nacm', 'true')
		else:
			nacm_root.newChild(None, 'enable-nacm', 'false')

		if self.external_groups:
			nacm_root.newChild(None, 'enable-external-groups', 'true')
		else:
			nacm_root.newChild(None, 'enable-external-groups', 'false')

		if self.r_default == acm.action.PERMIT:
			nacm_root.newChild(None, 'read-default', 'permit')
		else:
			nacm_root.newChild(None, 'read-default', 'deny')

		if self.w_default == acm.action.PERMIT:
			nacm_root.newChild(None, 'write-default', 'permit')
		else:
			nacm_root.newChild(None, 'write-default', 'deny')

		if self.x_default == acm.action.PERMIT:
			nacm_root.newChild(None, 'exec-default', 'permit')
		else:
			nacm_root.newChild(None, 'exec-default', 'deny')

		if self.groups or self.almighty_users:
			nacm_groups = nacm_root.newChild(None, 'groups', None)

			if self.almighty_users:
				nacm_group = nacm_groups.newChild(None, 'group', None)
				nacm_group.newChild(None, 'name', 'almighty')
				for user in self.almighty_users:
					nacm_group.newChild(None, 'user-name', user)

			for group in self.groups:
				nacm_group = nacm_groups.newChild(None, 'group', None)
				nacm_group.newChild(None, 'name', group.name)
				for user in group.users:
					nacm_group.newChild(None, 'user-name', user)

		if self.almighty_groups or self.almighty_users:
			nacm_rule_list = nacm_root.newChild(None, 'rule-list', None)
			nacm_rule_list.newChild(None, 'name', 'almighty')
			if self.almighty_users:
				nacm_rule_list.newChild(None, 'group', 'almighty')
			for group in self.almighty_groups:
				nacm_rule_list.newChild(None, 'group', group)

			nacm_rule = nacm_rule_list.newChild(None, 'rule', None)
			nacm_rule.newChild(None, 'name', 'almighty-operations')
			nacm_operation = nacm_rule.newChild(None, 'protocol-operation', None)
			nacm_operation.newChild(None, 'operation-name', '*')
			nacm_rule.newChild(None, 'action', 'allow')
			nacm_rule.newChild(None, 'comment', 'Rule defined using netopeer-configurator.')

			nacm_rule = nacm_rule_list.newChild(None, 'rule', None)
			nacm_rule.newChild(None, 'name', 'almighty-notofications')
			nacm_notification = nacm_rule.newChild(None, 'notification', None)
			nacm_notification.newChild(None, 'notification-name', '*')
			nacm_rule.newChild(None, 'action', 'allow')
			nacm_rule.newChild(None, 'comment', 'Rule defined using netopeer-configurator.')

			nacm_rule = nacm_rule_list.newChild(None, 'rule', None)
			nacm_rule.newChild(None, 'name', 'almighty-data')
			nacm_data = nacm_rule.newChild(None, 'data-node', None)
			nacm_data.newChild(None, 'path', '/')
			nacm_rule.newChild(None, 'action', 'allow')
			nacm_rule.newChild(None, 'comment', 'Rule defined using netopeer-configurator.')

		for rule_list in self.rule_lists:
			nacm_rule_list = nacm_root.newChild(None, 'rule-list', None)
			nacm_rule_list.newChild(None, 'name', rule_list.name)

			for group in rule_list.groups:
				nacm_rule_list.newChild(None, 'group', group)

			for rule in rule_list.rules:
				nacm_rule = nacm_rule_list.newChild(None, 'rule', None)
				nacm_rule.newChild(None, 'name', rule.name)
				if rule.module:
					nacm_rule.newChild(None, 'module-name', rule.module)
				if rule.type == acm.rule_type.OPERATION:
					nacm_operation = nacm_rule.newChild(None, 'protocol-operation', None)
					nacm_operation.newChild(None, 'operation-name', rule.identificator)
				elif rule.type == acm.rule_type.NOTIFICATION:
					nacm_notification = nacm_rule.newChild(None, 'notification', None)
					nacm_notification.newChild(None, 'notification-name', rule.identificator)
				elif rule.type == acm.rule_type.DATA:
					nacm_data = nacm_rule.newChild(None, 'data-node', None)
					nacm_data.newChild(None, 'path', rule.identificator)

			if rule.operations:
				nacm_rule.newChild(None, 'access-operations', ' '.join(rule.operations))

			if rule.action == acm.action.DENY:
				nacm_rule.newChild(None, 'action', 'deny')
			else:
				nacm_rule.newChild(None, 'action', 'allow')

			if rule.comment:
				nacm_rule.newChild(None, 'comment', rule.comment)

		try:
			nacm_datastore = open(self.datastore_path, 'w')
			nacm_datastore.write(nacm_doc.serialize(encoding='UTF-8', format=1))
		except IOError:
			messages.append('Failed to write Access Control configuration to file %s' % self.datastore_path)
			return(False)

		return(True)

	def paint(self, window, focus, height, width):
		window.addstr('Path to NACM datastore:\n')
		tools = []
		if focus and self.selected == 0:
			window.addstr('{s}\n'.format(s=self.datastore_path), curses.color_pair(1))
			tools.append(('e','edit'))
		else:
			window.addstr('{s}\n'.format(s=self.datastore_path), curses.color_pair(2))
		window.addstr('\n')
		if focus and self.selected == 1:
			if self.enabled:
				window.addstr('Access control is ON\n', curses.color_pair(1))
				tools.append(('c','disable'))
			else:
				window.addstr('Access control is OFF\n', curses.color_pair(1))
				tools.append(('c','enable'))
		else:
			if self.enabled:
				window.addstr('Access control is ON\n', curses.color_pair(2))
			else:
				window.addstr('Access control is OFF\n', curses.color_pair(2))

		if focus and self.selected == 2:
			if self.external_groups:
				window.addstr('Using system groups is ALLOWED\n', curses.color_pair(1))
				tools.append(('c','forbid'))
			else:
				window.addstr('Using system groups is FORBIDDEN\n', curses.color_pair(1))
				tools.append(('c','allow'))
		else:
			if self.external_groups:
				window.addstr('Using system groups is ALLOWED\n', curses.color_pair(2))
			else:
				window.addstr('Using system groups is FORBIDDEN\n', curses.color_pair(2))
		window.addstr('\n')

		if focus and self.selected == 3:
			if self.r_default == acm.action.DENY:
				window.addstr('Default action for read requests: DENY\n', curses.color_pair(1))
				tools.append(('c','permit'))
			else:
				window.addstr('Default action for read requests: PERMIT\n', curses.color_pair(1))
				tools.append(('c','deny'))
		else:
			if self.r_default == acm.action.DENY:
				window.addstr('Default action for read requests: DENY\n', curses.color_pair(2))
			else:
				window.addstr('Default action for read requests: PERMIT\n', curses.color_pair(2))

		if focus and self.selected == 4:
			if self.w_default == acm.action.PERMIT:
				window.addstr('Default action for write requests: PERMIT\n', curses.color_pair(1))
				tools.append(('c','deny'))
			else:
				window.addstr('Default action for write requests: DENY\n', curses.color_pair(1))
				tools.append(('c','permit'))
		else:
			if self.w_default == acm.action.PERMIT:
				window.addstr('Default action for write requests: PERMIT\n', curses.color_pair(2))
			else:
				window.addstr('Default action for write requests: DENY\n', curses.color_pair(2))

		if focus and self.selected == 5:
			if self.x_default == acm.action.DENY:
				window.addstr('Default action for execute requests: DENY\n', curses.color_pair(1))
				tools.append(('c','permit'))
			else:
				window.addstr('Default action for execute requests: PERMIT\n', curses.color_pair(1))
				tools.append(('c','deny'))
		else:
			if self.x_default == acm.action.DENY:
				window.addstr('Default action for execute requests: DENY\n', curses.color_pair(2))
			else:
				window.addstr('Default action for execute requests: PERMIT\n', curses.color_pair(2))
		window.addstr('\n')

		if focus and self.selected == 6:
			if self.almighty_users:
				window.addstr('Users with ulimited access priviledges. You can add some.\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Currently there are no users with ulimited access priviledges. You can add some.\n', curses.color_pair(1))
				tools.append(('a','add'))
		else:
			if self.almighty_users:
				window.addstr('Users with ulimited access priviledges. You can add some.\n', curses.color_pair(2))
			else:
				window.addstr('Currently there are no users with ulimited access priviledges. You can add some.\n', curses.color_pair(2))

		for user in self.almighty_users:
			if focus and self.selected == (self.almighty_users.index(user)+7):
				window.addstr('{s}\n'.format(s=user), curses.color_pair(1))
				tools.append(('a','add'))
				tools.append(('d','delete'))
				tools.append(('e','edit'))
			else:
				window.addstr('{s}\n'.format(s=user), curses.color_pair(2))
		window.addstr('\n')

		if focus and self.selected == 7+len(self.almighty_users):
			if self.almighty_groups:
				window.addstr('Groups with ulimited access priviledges. You can add some.\n', curses.color_pair(1))
				tools.append(('a','add'))
			else:
				window.addstr('Currently there are no groups with ulimited access priviledges. You can add some.\n', curses.color_pair(1))
				tools.append(('a','add'))
		else:
			if self.almighty_groups:
				window.addstr('Groups with ulimited access priviledges. You can add some.\n', curses.color_pair(2))
			else:
				window.addstr('Currently there are no groups with ulimited access priviledges. You can add some.\n', curses.color_pair(2))

		for group in self.almighty_groups:
			if focus and self.selected == (self.almighty_groups.index(group)+len(self.almighty_users)+8):
				window.addstr('{s}\n'.format(s=group), curses.color_pair(1))
				tools.append(('a','add'))
				tools.append(('d','delete'))
				tools.append(('e','edit'))
			else:
				window.addstr('{s}\n'.format(s=group), curses.color_pair(2))
		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < 7+len(self.almighty_users)+len(self.almighty_groups):
			self.selected = self.selected+1
		elif key == ord('c'):
			if self.selected == 1:
				self.enabled = not(self.enabled)
			elif self.selected == 2:
				self.external_groups = not(self.external_groups)
			elif self.selected == 3:
				if self.r_default == acm.action.PERMIT:
					self.r_default = acm.action.DENY
				else:
					self.r_default = acm.action.PERMIT
			elif self.selected == 4:
				if self.w_default == acm.action.PERMIT:
					self.w_default = acm.action.DENY
				else:
					self.w_default = acm.action.PERMIT
			elif self.selected == 5:
				if self.x_default == acm.action.PERMIT:
					self.x_default = acm.action.DENY
				else:
					self.x_default = acm.action.PERMIT
			else:
				curses.flash()
		elif key == ord('e'):
			if self.selected == 0:
				# edit file path
				tmp_nacm_var = self.get_editable(1,0, stdscr, window, self.datastore_path, curses.color_pair(1))
				if tmp_nacm_var and os.path.isfile(tmp_nacm_var):
					self.datastore_path = tmp_nacm_var
					self.get()
				else:
					try:
						open(tmp_nacm_var, 'w').close()
						self.datastore_path = tmp_nacm_var
						self.get()
					except IOError:
						messages.append('{s} is not valid file and can not be created.'.format(s=tmp_nacm_var))
			elif self.selected in range(7,7+len(self.almighty_users)):
				# edit user
				pos = self.selected-7
				tmp_nacm_var = self.get_editable(self.selected+4,0, stdscr, window, self.almighty_users[pos], curses.color_pair(1))
				if tmp_nacm_var:
					self.almighty_users[pos] = tmp_nacm_var
				else:
					messages.append('{s} is not valid username.'.format(s=tmp_nacm_var))
			elif self.selected in range(8+len(self.almighty_users), 8+len(self.almighty_users)+len(self.almighty_groups)):
				# edit group
				pos = self.selected-(8+len(self.almighty_users))
				tmp_nacm_var = self.get_editable(self.selected+5,0, stdscr, window, self.almighty_groups[pos], curses.color_pair(1))
				if tmp_nacm_var:
					self.almighty_groups[pos] = tmp_nacm_var
				else:
					messages.append('{s} is not valid groupname.'.format(s=tmp_nacm_var))
			else:
				curses.flash()
		elif key == ord('a'):
			if self.selected in range(6,7+len(self.almighty_users)):
				# add user
				tmp_nacm_var = self.get_editable(11+len(self.almighty_users),0, stdscr, window, '', curses.color_pair(1))
				if tmp_nacm_var:
					self.almighty_users.append(tmp_nacm_var)
				else:
					messages.append('{s} is not valid username.'.format(s=tmp_nacm_var))
			elif self.selected in range(7+len(self.almighty_users), 8+len(self.almighty_users)+len(self.almighty_groups)):
				# add group
				pos = self.selected-(8+len(self.almighty_users))
				tmp_nacm_var = self.get_editable(13+len(self.almighty_users)+len(self.almighty_groups),0, stdscr, window, '', curses.color_pair(1))
				if tmp_nacm_var:
					self.almighty_groups.append(tmp_nacm_var)
				else:
					messages.append('{s} is not valid groupname.'.format(s=tmp_nacm_var))
			else:
				curses.flash()
		elif key == ord('d'):
			if self.selected in range(7,7+len(self.almighty_users)):
				# remove user
				pos = self.selected-7
				self.almighty_users.remove(self.almighty_users[pos])
				pass
			elif self.selected in range(8+len(self.almighty_users), 8+len(self.almighty_users)+len(self.almighty_groups)):
				# remove group
				pos = self.selected-(8+len(self.almighty_users))
				self.almighty_groups.remove(self.almighty_groups[pos])
				pass
			else:
				curses.flash()
		else:
			curses.flash()
		return(True)

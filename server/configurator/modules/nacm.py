#!/usr/bin/python
# -*- coding:utf-8 -*-

import curses
import os
import libxml2
import subprocess
import nc_module
import messages

linewidth = 50

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
	nacm_doc = None
	nacm_ctxt = None
	print_rules_flag = 1
	
	enabled = True
	extgroups = True
	r_default = acm.action.PERMIT
	w_default = acm.action.DENY
	x_default = acm.action.PERMIT
	
	xml_enabled = None
	xml_extgroups = None
	xml_r_default = None
	xml_w_default = None
	xml_x_default = None

	nacm_group_names = []
	almighty_users = []
	almighty_group = None
	
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

		try:
			datastore = open(os.path.join(ncworkingdir, 'datastore-acm.xml'), 'a')
		except:
			return(False)
			
		self.datastore_path = os.path.join(ncworkingdir, 'datastore-acm.xml')
		if os.path.getsize(self.datastore_path) == 0:
			# create basic structure
			datastore.write('<?xml version="1.0" encoding="UTF-8"?>\n<datastores xmlns="urn:cesnet:tmc:datastores:file">\n  <running lock=""/>\n  <startup lock=""/>\n  <candidate modified="false" lock=""/>\n</datastores>')
		
		datastore.close()
		return(True)

	def get(self):
		if not self.datastore_path:
			messages.append('Path to NACM datastore not specified.', 'error')
			return(False)

		try:
			self.nacm_doc = libxml2.readFile(self.datastore_path, None, libxml2.XML_PARSE_NOERROR|libxml2.XML_PARSE_NOWARNING)
		except:
			messages.append('Can not parse Access Control configuration. File %s is probably corrupted.' % self.datastore_path, 'warning')
			return(False)

		self.nacm_ctxt = self.nacm_doc.xpathNewContext()
		self.nacm_ctxt.xpathRegisterNs('d', 'urn:cesnet:tmc:datastores:file')
		self.nacm_ctxt.xpathRegisterNs('n', 'urn:ietf:params:xml:ns:yang:ietf-netconf-acm')

		list = self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:enable-nacm')
		if list :
			self.xml_enabled = list[0]
		if self.xml_enabled and self.xml_enabled.get_content() == 'false':
			self.enabled = False
		else:
			self.enabled = True
		
		list = self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:enable-external-groups')
		if list :
			self.xml_extgroups = list[0]
		if self.xml_extgroups and self.xml_extgroups.get_content() == 'false':
			self.extgroups = False
		else:
			self.extgroups = True
			
		list = self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:read-default')
		if list :
			self.xml_r_default = list[0]
		if self.xml_r_default and self.xml_r_default.get_content() == 'deny':
			self.r_default = acm.action.DENY
		else:
			self.r_default = acm.action.PERMIT
			
		list = self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:write-default')
		if list :
			self.xml_w_default = list[0]
		if self.xml_w_default and self.xml_w_default.get_content() == 'permit':
			self.w_default = acm.action.PERMIT
		else:
			self.w_default = acm.action.DENY
			
		list = self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:exec-default')
		if list :
			self.xml_x_default = list[0]
		if self.xml_x_default and self.xml_x_default.get_content() == 'deny':
			self.x_default = acm.action.DENY
		else:
			self.x_default = acm.action.PERMIT
			
		self.nacm_group_names = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:groups/n:group/n:name'))
		
		if 'almighty' in self.nacm_group_names:
			self.almighty_users = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:groups/n:group[n:name=\'almighty\']/n:user-name'))
			self.almighty_group = self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:groups/n:group[n:name=\'almighty\']')[0]
			
		return(True)

	def print_rules(self, window):

		for group_name in self.nacm_group_names:
			window.addstr('\nGroup {s}:\n'.format(s=group_name))
			group_users = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:groups/n:group[n:name=\'{s}\']/n:user-name'.format(s=group_name)))
			for user in group_users:
				window.addstr('  {s}\n'.format(s=user))
				
		nacm_rule_lists = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list/n:name'))
		for rule_list_name in nacm_rule_lists:
			window.addstr('\nRule list {s}:\n'.format(s=rule_list_name))
			window.addstr('  Group(s): ')
			groups = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{s}\']/n:group'.format(s=rule_list_name)))
			for group in groups:
				window.addstr('{s} '.format(s=group))
			window.addstr('\n')
			
			rule_names = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{s}\']/n:rule/n:name'.format(s=rule_list_name)))
			for rule_name in rule_names:
				window.addstr('  Rule {s}:\n'.format(s=rule_name))
				module_names = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[n:name=\'{rule}\']/n:module-name'.format(list=rule_list_name,rule=rule_name)))
				if module_names:
					window.addstr('    Module: {s}\n'.format(s=module_names[0]))
				
				rpc_names = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[n:name=\'{rule}\']/n:protocol-operation/n:rpc-name'.format(list=rule_list_name,rule=rule_name)))
				if rpc_names:
					window.addstr('    RPC: {s}\n'.format(s=rpc_names[0]))
				
				notification_name = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[n:name=\'{rule}\']/n:notification/n:notification-name'.format(list=rule_list_name,rule=rule_name)))
				if notification_name:
					window.addstr('    Notification: {s}\n'.format(s=notification_name[0]))
					
				data_path = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[n:name=\'{rule}\']/n:data-node/n:path'.format(list=rule_list_name,rule=rule_name)))
				if data_path:
					window.addstr('    Data Path: {s}\n'.format(s=data_path[0]))
					
				access_operation = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[n:name=\'{rule}\']/n:access-operations'.format(list=rule_list_name,rule=rule_name)))
				if access_operation:
					window.addstr('    Access Operation(s): {s}\n'.format(s=access_operation[0]))
				
				action = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[n:name=\'{rule}\']/n:action'.format(list=rule_list_name,rule=rule_name)))
				if action:
					window.addstr('    Action: {s}\n'.format(s=action[0]))
				
				comment = map(libxml2.xmlNode.get_content, self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:rule-list[n:name=\'{list}\']/n:rule[n:name=\'{rule}\']/n:comment'.format(list=rule_list_name,rule=rule_name)))
				if comment:
					window.addstr('    Comment: {s}\n'.format(s=comment[0]))

		return(True)

	def update(self):
		if not self.datastore_path:
			messages.append('Path to NACM datastore not specified.', 'error')
			return(False)

		xpath_nacm = self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm')
		if not xpath_nacm:
			xpath_startup = self.nacm_ctxt.xpathEval('/d:datastores/d:startup')
			if not xpath_startup:
				messages.append('Invalid datastore content, unable to modify.', 'error')
				return(False)
			else:
				startup = xpath_startup[0]
			nacm = startup.newChild(None, 'nacm', None)
			nacm.newNs('urn:ietf:params:xml:ns:yang:ietf-netconf-acm', None)
		else:
			nacm = xpath_nacm[0]
				
		if not self.almighty_group and self.almighty_users:
			# create the almighty rule			
			if nacm.children:
				almighty_rulelist = nacm.children.addPrevSibling(libxml2.newNode('rule-list'))
			else:
				almighty_rulelist = nacm.newChild(nacm.ns(), 'rule-list', None)
			almighty_rulelist.setNs(nacm.ns())
			almighty_rulelist.newChild(nacm.ns(), 'name', 'almighty')
			almighty_rulelist.newChild(nacm.ns(), 'group', 'almighty')
			almighty_rule = almighty_rulelist.newChild(nacm.ns(), 'rule', None)
			almighty_rule.newChild(nacm.ns(), 'name', 'almighty')
			almighty_rule.newChild(nacm.ns(), 'module-name', '*')
			almighty_rule.newChild(nacm.ns(), 'access-operations', '*')
			almighty_rule.newChild(nacm.ns(), 'action', 'permit')
			
			# create the almighty group
			xpath_groups = self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:groups')
			if not xpath_groups:
				groups = nacm.newChild(nacm.ns(), 'groups', None)
			else:
				groups = xpath_groups[0]
			self.almighty_group = groups.newChild(nacm.ns(), 'group', None)
			self.almighty_group.newChild(nacm.ns(), 'name', 'almighty')
			for user in self.almighty_users:
				self.almighty_group.newChild(nacm.ns(), 'user-name', user)
		else:
			# update
			# remove almighty users
			xpath_users = self.nacm_ctxt.xpathEval('/d:datastores/d:startup/n:nacm/n:groups/n:group[n:name=\'almighty\']/n:user-name')
			for node in xpath_users:
				node.unlinkNode()
				node.freeNode()
			# add current almighty users
			for user in self.almighty_users:
				self.almighty_group.newChild(nacm.ns(), 'user-name', user)

		if self.xml_enabled:
			self.xml_enabled.setContent('true' if self.enabled else 'false')
		elif not self.enabled:
			self.xml_enabled = nacm.newChild(nacm.ns(), 'enable-nacm', 'false')

		if self.xml_extgroups:
			self.xml_extgroups.setContent('true' if self.extgroups else 'false')
		elif not self.extgroups:
			self.xml_extgroups = nacm.newChild(nacm.ns(), 'enable-external-groups', 'false')
		
		if self.xml_r_default:
			self.xml_r_default.setContent('deny' if self.r_default == acm.action.DENY else 'permit')
		elif self.r_default == acm.action.DENY:
			self.xml_r_default = nacm.newChild(nacm.ns(), 'read-default', 'deny')
		
		if self.xml_w_default:
			self.xml_w_default.setContent('deny' if self.w_default == acm.action.DENY else 'permit')
		elif self.w_default == acm.action.PERMIT:
			self.xml_w_default = nacm.newChild(nacm.ns(), 'write-default', 'permit')
			
		if self.xml_x_default:
			self.xml_x_default.setContent('deny' if self.x_default == acm.action.DENY else 'permit')
		elif self.x_default == acm.action.DENY:
			self.xml_x_default = nacm.newChild(nacm.ns(), 'exec-default', 'deny')
			
		try:
			nacm_datastore = open(self.datastore_path, 'w')
			nacm_datastore.write(self.nacm_doc.serialize(encoding='UTF-8', format=1))
			nacm_datastore.close
		except IOError:
			messages.append('Failed to write NACM configuration to file %s' % self.datastore_path, 'error')
			return(False)

		return(True)

	def paint(self, window, focus, height, width):
		window.addstr('Path to NACM datastore:\n')
		tools = []
		msg = '{s}'.format(s=self.datastore_path)
		if len(msg) > 50:
			global linewidth
			linewidth = len(msg)

		if focus:
			tools.append(('ENTER','change'))
			tools.append(('selected',str(self.selected)))
				
		window.addstr(msg+' '*(linewidth-len(msg))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 0 else 0)
		window.addstr('\n')
		
		# NACM enabled/disabled
		if self.enabled:
			msg = 'Access control is ON'
		else:
			msg = 'Access control is OFF'
		window.addstr(msg+' '*(linewidth-len(msg))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 1 else 0)
			
		# NACM system groups usage
		if self.extgroups:
			msg = 'Using system groups is ALLOWED'
		else:
			msg = 'Using system groups is FORBIDDEN'
		window.addstr(msg+' '*(linewidth-len(msg))+'\n\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 2 else 0)
		
		# default read permission
		if self.r_default == acm.action.DENY:
			msg = 'Default action for read requests: DENY'
		else:
			msg = 'Default action for read requests: PERMIT'
		window.addstr(msg+' '*(linewidth-len(msg))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 3 else 0)
		
		# default write permission
		if self.w_default == acm.action.DENY:
			msg = 'Default action for write requests: DENY'
		else:
			msg = 'Default action for write requests: PERMIT'
		window.addstr(msg+' '*(linewidth-len(msg))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 4 else 0)
			
		# default execute permission
		if self.x_default == acm.action.DENY:
			msg = 'Default action for execute requests: DENY'
		else:
			msg = 'Default action for execute requests: PERMIT'
		window.addstr(msg+' '*(linewidth-len(msg))+'\n\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 5 else 0)

		msg = 'Add users with unlimited access'
		window.addstr(msg+' '*(linewidth-len(msg))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 6 else 0)
		if self.almighty_users:
			for user in self.almighty_users:
				msg = '  {s}'.format(s=user)
				window.addstr(msg+' '*(linewidth-len(msg))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == self.almighty_users.index(user)+7 else 0)
		window.addstr('\n')
		
		if self.print_rules_flag:
			msg = 'Hide current NACM rules.'
			window.addstr(msg+' '*(linewidth-len(msg))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 7+len(self.almighty_users) else 0)
			self.print_rules(window)
		else:
			msg = 'Show current NACM rules.'
			window.addstr(msg+' '*(linewidth-len(msg))+'\n', curses.color_pair(0) | curses.A_REVERSE if focus and self.selected == 7+len(self.almighty_users) else 0)
		
		return(tools)

	def handle(self, stdscr, window, height, width, key):
		if key == curses.KEY_UP and self.selected > 0:
			self.selected = self.selected-1
		elif key == curses.KEY_DOWN and self.selected < 7 + len(self.almighty_users):
			self.selected = self.selected+1
		elif key == ord('\n'):
			if self.selected == 0:
				window.addstr(1, 0, ' '*linewidth,  curses.color_pair(0))
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
						messages.append('{s} is not valid file and can not be created.'.format(s=tmp_nacm_var), 'error')
			elif self.selected == 1:
				self.enabled = not(self.enabled)
			elif self.selected == 2:
				self.extgroups = not(self.extgroups)
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
			elif self.selected in range(6, len(self.almighty_users) + 7):
				window.addstr(11+len(self.almighty_users), 0, '> _'+' '*(linewidth-3),  curses.color_pair(0))
				if self.selected == 6:
					# add new user
					tmp_nacm_var = self.get_editable(11+len(self.almighty_users), 2, stdscr, window, '', curses.color_pair(1) | curses.A_REVERSE)
				else:
					# edit user
					pos = self.selected-7
					tmp_nacm_var = self.get_editable(11+len(self.almighty_users), 2, stdscr, window, self.almighty_users[pos], curses.color_pair(1))
					
				if tmp_nacm_var:
					if self.selected == 6 and self.almighty_users.count(tmp_nacm_var):
						# adding user that already present in the list
						messages.append('User \'{s}\' already present in the list'.format(s=tmp_nacm_var), 'error')
						curses.flash()
						return(True)
					elif self.selected == 6:
						# adding a new user that is not yet in the list
						self.almighty_users.append(tmp_nacm_var)
					else:
						# editing the current user
						self.almighty_users.remove(self.almighty_users[pos])
						self.almighty_users.append(tmp_nacm_var)
					
					self.almighty_users.sort()	
					self.selected = self.almighty_users.index(tmp_nacm_var) + 7
				elif self.selected != 6:
					# removing an existing user from the list
					self.almighty_users.remove(self.almighty_users[pos])
				else:
					# adding empty user	
					messages.append('Invalid empty user', 'error')
					curses.flash()
					return(True)
			elif self.selected == len(self.almighty_users) + 7:
				self.print_rules_flag = not self.print_rules_flag
			else:
				curses.flash()
		else:
			curses.flash()
		return(True)

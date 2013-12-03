"""Tree output plugin

Idea copied from libsmi.
Created from tree plugin
"""

import optparse
import sys
import re
import string

from pyang import plugin
from pyang import statements

def pyang_plugin_init():
    plugin.register_plugin(ResptemplPlugin())

class ResptemplPlugin(plugin.PyangPlugin):
    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['resptempl'] = self

    def add_opts(self, optparser):
        optlist = [
            optparse.make_option("--resptempl-help",
                                 dest="resptempl_help",
                                 action="store_true",
                                 help="Print help on tree symbols and exit"),
            optparse.make_option("--resptempl-depth",
                                 type="int",
                                 dest="resptempl_depth",
                                 help="Number of levels to print"),
            optparse.make_option("--resptempl-config",
                                 type="int",
                                 dest="resptempl_config",
                                 help="Generate config or state tree? 1 for config otherwise state."),
            optparse.make_option("--resptempl-path",
                                 dest="resptempl_path",
                                 help="Subtree to print"),
            ]
        g = optparser.add_option_group("Response template output specific options")
        g.add_options(optlist)

    def setup_ctx(self, ctx):
        if ctx.opts.resptempl_help:
            print_help()
            sys.exit(0)

    def setup_fmt(self, ctx):
        ctx.implicit_errors = False

    def emit(self, ctx, modules, fd):
        if ctx.opts.resptempl_path is not None:
            path = string.split(ctx.opts.resptempl_path, '/')
            if path[0] == '':
                path = path[1:]
        else:
            path = None
	if ctx.opts.resptempl_config:
		resptempl_config = (ctx.opts.resptempl_config == 1)
	else:
		resptempl_config = False
	print resptempl_config
        emit_resptempl(modules, fd, ctx.opts.resptempl_depth, path, resptempl_config)

def print_help():
    print """
Each node is printed as:

"""    

def emit_resptempl(modules, fd, depth, path, config):
    for module in modules:
        bstr = ""
        b = module.search_one('belongs-to')
        if b is not None:
            bstr = " (belongs-to %s)" % b.arg
        #fd.write("%s: %s%s\n" % (module.keyword, module.arg, bstr))
        fd.write('<?xml version="1.0"?>\n')
        chs = [ch for ch in module.i_children
               if ch.keyword in statements.data_definition_keywords]
        if path is not None and len(path) > 0:
            chs = [ch for ch in chs
                   if ch.arg == path[0]]
            path = path[1:]

        print_children(chs, module, fd, ' ', path, depth, pcconfig=config)

        rpcs = module.search('rpc')
        if path is not None and len(path) > 0:
            rpcs = [rpc for rpc in rpcs
                    if rpc.arg == path[0]]
            path = path[1:]
        if len(rpcs) > 0:
            fd.write('<?xml version="1.0"?>\n')
            print_children(rpcs, module, fd, ' ', path, depth, pcconfig=config)

        notifs = module.search('notification')
        if path is not None and len(path) > 0:
            notifs = [n for n in notifs
                      if n.arg == path[0]]
            path = path[1:]
        if len(notifs) > 0:
            fd.write("notifications:\n")
            print_children(notifs, module, fd, ' ', path, depth, pcconfig=config)

def print_children(i_children, module, fd, prefix, path, depth, pcconfig, width=0):
    if depth == 0:
        return
    def get_width(w, chs):
        for ch in chs:
            if ch.keyword in ['choice', 'case']:
                w = get_width(w, ch.i_children)
            else:
                if ch.i_module.i_modulename == module.i_modulename:
                    nlen = len(ch.arg)
                else:
                    nlen = len(ch.i_module.i_prefix) + 1 + len(ch.arg)
                if nlen > w:
                    w = nlen
        return w
    
    if width == 0:
        width = get_width(0, i_children)

    for ch in i_children:
        if ch == i_children[-1]:
            newprefix = prefix + '   '
        else:
            newprefix = prefix + '  |'
        if ((ch.arg == 'input' or ch.arg == 'output') and
            ch.parent.keyword == 'rpc' and
            len(ch.i_children) == 0 and
            ch.parent.search_one(ch.arg) is None):
            pass
        else:
            print_node(ch, module, fd, newprefix, path, depth, width, pnconfig=pcconfig)

def find_nodes_by_state(nodes, conf):
	for n in nodes:
		if n.i_config == conf:
			return True
		else:
			if hasattr(n, "i_children"):
				if find_nodes_by_state(n.i_children, conf):
					return True
	return False

def print_node(s, module, fd, prefix, path, depth, width, pnconfig):
    ##fd.write("-%s-%s" % (prefix[0:-1], width))

    if s.i_module.i_modulename == module.i_modulename:
        name = s.arg
    else:
        name = s.i_module.i_prefix + ':' + s.arg
    flags = get_flags_str(s)
    if s.search_one('uses'):
    	if s.search_one('uses').arg.startswith('histogram'):
		if s.i_config == pnconfig:
			fd.write("<%s/>\n" % name)
			return
    if (hasattr(s, 'i_children') and s.i_children):
        if depth is not None:
            depth = depth - 1
        chs = s.i_children
        if path is not None and len(path) > 0:
            chs = [ch for ch in chs
                   if ch.arg == path[0]]
            path = path[1:]
	iscontent = find_nodes_by_state(chs, pnconfig)
	if iscontent:
		if name == "packet-sizes":
			print s, dir(s), 
		fd.write("<%s>\n" % name)
		if s.keyword in ['choice', 'case']:
		    print_children(chs, module, fd, prefix, path, depth, width, pcconfig=pnconfig)
		else:
		    print_children(chs, module, fd, prefix, path, depth, pcconfig=pnconfig)
		fd.write("</%s>\n" % name)
    else:
	if s.i_config == pnconfig:
	        fd.write("<%s/>\n" % name)
	#else:
	#	fd.write("<!-- <%s/> %s-->\n" % (name, s.i_config))

def get_status_str(s):
    status = s.search_one('status')
    if status is None or status.arg == 'current':
        return '+'
    elif status.arg == 'deprecated':
        return 'x'
    elif status.arg == 'obsolete':
        return 'o'

def get_flags_str(s):
    if s.keyword == 'rpc':
        return '-x'
    elif s.keyword == 'notification':
        return '-n'    
    elif s.i_config == True:
        return 'rw'
    else:
        return 'ro'

def get_typename(s):
    t = s.search_one('type')
    if t is not None:
        return t.arg
    else:
        return ''

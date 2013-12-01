"""NMP - Netopeer Model Processing plugin

Idea copied from libsmi.
Created from tree plugin
"""

import optparse
import sys
import re
import string
import os
import shutil
"""for debug"""
import pprint
import copy
import pdb

from pyang import plugin
from pyang import statements
from pyang import translators
from pyang.translators.yin import YINPlugin

CONFIG_STR="config"
STATE_STR="state"

def pyang_plugin_init():
    plugin.register_plugin(nmpPlugin())

class nmpPlugin(plugin.PyangPlugin):
    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['nmp'] = self

    def add_opts(self, optparser):
        optlist = [
            optparse.make_option("--nmp-help",
                                 dest="nmp_help",
                                 action="store_true",
                                 help="Print help on tree symbols and exit"),
            optparse.make_option("--nmp-depth",
                                 type="int",
                                 dest="nmp_depth",
                                 help="Number of levels to print"),
            optparse.make_option("--nmp-maxdepth",
                                 type="int",
                                 dest="nmp_maxdepth",
                                 default=2,
                                 help="How many subsection layers to create?"),
            optparse.make_option("--nmp-genidentifier",
                                 action="store_true",
                                 dest="nmp_genident",
                                 help="Generate identifier of model and exit"),
            optparse.make_option("--nmp-genrpc",
                                 action="store_true",
                                 dest="nmp_genrpc",
                                 help="Create rpc.yin output with RPC operations"),
            optparse.make_option("--nmp-minchildsec",
                                 type="int",
                                 dest="nmp_minchildsec",
                                 default=3,
                                 help="Minimal amount of children to leave in section."),
            optparse.make_option("--nmp-breaktree",
                                 action="store_true",
                                 dest="nmp_breaktree",
                                 help="Remove config or state tree."),
            optparse.make_option("--nmp-config",
                                 action="store_true",
                                 dest="nmp_config",
                                 help="Generate config or state tree? Generate config if set, otherwise state."),
            optparse.make_option("--nmp-outputdir",
                                 type="string",
                                 dest="nmp_outputdir",
                                 help="Where to generate directory tree?"),
            optparse.make_option("--nmp-path",
                                 dest="nmp_path",
                                 help="Subtree to print"),
            optparse.make_option("--nmp-hostname",
                                 dest="nmp_hostname",
				 type="string",
				 default="",
                                 help="Hostname of device that provided model (via get-schema)"),
            optparse.make_option("--nmp-port",
                                 dest="nmp_port",
				 type="string",
				 default="",
                                 help="Network port of connection to device that provided model (via get-schema)"),
            optparse.make_option("--nmp-username",
                                 dest="nmp_username",
				 type="string",
				 default="",
                                 help="Username used for connection to device that provided model (via get-schema)"),
            ]
        g = optparser.add_option_group("Netopeer Model Processing plugin specific options")
        g.add_options(optlist)

    def setup_ctx(self, ctx):
        if ctx.opts.nmp_help:
            print_help()
            sys.exit(0)

    def setup_fmt(self, ctx):
        ctx.implicit_errors = False

    def emit(self, ctx, modules, fd):
        if not ctx.opts.nmp_maxdepth:
            ctx.opts.nmp_maxdepth = 2
        if not ctx.opts.nmp_minchildsec:
            ctx.opts.nmp_minchildsec = 2
	if ctx.opts.nmp_config:
		ctx.opts.nmp_config = (ctx.opts.nmp_config == 1)
	else:
		ctx.opts.nmp_config = False
        pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(dir())
        #pp.pprint(vars(self))
        #pp.pprint(vars(ctx.repository))
        #pp.pprint(dir(modules))
        #pp.pprint(fd)
	#pp.pprint(ctx.opts)
        emit_nmp(modules, fd, ctx)

def print_help():
    print """
TODO help
"""    
def create_sect_dir(path):
    #print "Creation of directory: %s" % path
    try:
        os.makedirs(path)
    except:
        print "Cannot create directory \"%s\"" % path
        pass

class Separator():
    def __init__(self, depth, path, statement):
        self.depth = depth
        self.path = path
        self.statement = statement
    def __str__(self):
        return "SEPARATOR %i %s %s" % (self.depth, self.path, self.statement.arg)

def remove_elemtype(root, conftype):
    """Remove all elements which are configuration or state.

    root - root element
    conftype - list of element types to remove (the rest is not mentioned)
        ["config", "state"]"""

    if not conftype:
        #print "!!!!NO CONFTYPE!!!!", root.arg, root.keyword, conftype
        return False
    #print "Called remove_elemtype", conftype
    empty = True
    if hasattr(root, "i_children") and root.i_children:
        for n in root.i_children:
            # go through all subtrees
            if not empty:
                remove_elemtype(n, conftype)
            else:
                empty = remove_elemtype(n, conftype)
    #print "Config of element", root.arg, root.i_config
    # subtrees are solved

    if not empty:
        #print "Cannot remove non-empty", root.arg, conftype
        return False

    doRemove = False
    if (CONFIG_STR in conftype):
        #remove configuration
        if root.i_config == True:
            doRemove = True
    if (STATE_STR in conftype):
        #remove state
        if root.i_config == False:
            doRemove = True
    if doRemove:
        removed=False
        try:
            index = root.parent.substmts.index(root)
            root.parent.substmts.pop(index)
            #print "REMOVEDsu", root.arg, conftype, root.i_config, empty
            return True
        except ValueError:
            #print "NOT FOUND", root.arg, root.keyword
            return False
    else:
        #print "NOT REMOVED", root.arg, conftype, root.i_config, empty
        return False
            
def statement_copyrec(parent,origstmt):
    new = copy.copy(origstmt)
    new.parent = parent
    new.top = None

    if hasattr(origstmt, "substmts"):
        new.substmts = []
        for s in origstmt.substmts:
            new.substmts.append(statement_copyrec(new,s))
    if hasattr(origstmt, "i_children"):
        new.i_children = []
        for s in origstmt.i_children:
            new.i_children.append(statement_copyrec(new,s))
    return new
    

def statement_deepcopy(origstmt):
    """origstmt should be root element"""
    return statement_copyrec(None,origstmt)


def save_model_part(ctx, root_element, filepath, modeltype):
    """Save YIN part of model into file in filepath"""

    #remove state if modeltype is not "config"
    if ctx.opts.nmp_breaktree:
        if modeltype in [CONFIG_STR, STATE_STR]:
            if modeltype == CONFIG_STR:
                remove_elemtype(root_element, STATE_STR)
            else:
                remove_elemtype(root_element, CONFIG_STR)
    else:
        modeltype = "getpart"

    modelpart = open(filepath + "/" + modeltype + ".yin", "w")
    yin = YINPlugin()
    yin.emit(ctx, [root_element], modelpart)
    modelpart.close()

def dive_into_section_queue(section, fd, ctx, curpath, maxdepth):
    queue = [section]
    p = pprint.PrettyPrinter();
    while queue:
        node = queue.pop(0)
        if isinstance(node, Separator):
            print node #separator
            continue
        elif isinstance(node, list):
            if not node:
              continue
            print "start"
            for i in node:
                if hasattr(i, "i_children") and i.i_children:
                    queue.append(i.i_children)
                else:
                    print "\tleaf", i.arg, i.keyword
            print "stop"
        else:
            print "\t", node.arg, node.keyword
            if hasattr(node, "i_children") and node.i_children:
                queue.append(node.i_children)
            #queue.append(Separator(depth, curpath, node.parent))
    return

def generate_filter(subcurpath, subsection, namespace):
    filterfile = open(subcurpath + "/filter.txt", "w")

    #pdb.set_trace()
    if not hasattr(subsection, "parent") or subsection.parent.keyword == "module":
        filterstr = "<%s xmlns=\"%s\"/>" % (subsection.arg, namespace)
        cn = None
    else:
        filterstr = "<%s/>" % subsection.arg
        cn = subsection.parent

    while cn:
        key = cn.search_one('key')
        if key:
            #iterate over words in <key>
            for i in re.finditer(r'\S+', key.arg):
                filterstr = "<%s/>%s" % (i.group(0), filterstr)
        else:
            #print "No key for", cn.arg, cn.keyword
            pass
        if (cn.parent and cn.parent.keyword == "module") or cn.keyword == "module":
            filterstr = "<%s xmlns=\"%s\">%s</%s>" % (cn.arg, namespace, filterstr, cn.arg)
            break
        else:
            filterstr = "<%s>%s</%s>" % (cn.arg, filterstr, cn.arg)
        cn = cn.parent
    filterfile.write(filterstr)
    filterfile.write("\n")
    filterfile.close()

def dive_into_section(section, fd, ctx, curpath, maxdepth, modelname, namespace):
    """ Iterate over model and create submodels
    modelname - string, name of output file"""
    maxdepth -= 1
    #pdb.set_trace()
    #print vars(section)
    if hasattr(section, "i_children"):
        for subsection in section.i_children:
            if subsection.keyword in ["container", "list"]:
                if subsection.parent.i_children.__len__() >= ctx.opts.nmp_minchildsec and subsection.arg !="data":
                    subcurpath = curpath + "/" + subsection.arg
                    create_sect_dir(subcurpath)

                    generate_filter(subcurpath, subsection, namespace)

                    if maxdepth > 0:
                        dive_into_section(subsection, fd, ctx, copy.deepcopy(curpath), maxdepth, modelname, namespace)
                    else:
                        save_model_part(ctx, subsection, subcurpath, modelname)
                else:
                    dive_into_section(subsection, fd, ctx, copy.deepcopy(curpath), maxdepth, modelname, namespace)
                    
    else:
        save_model_part(ctx, section, curpath, modelname)

def generate_identifier(module, ctx):
    revnodes = module.search("revision")
    revisions = []
    for rev in revnodes:
        revisions.append(rev.arg)
    revisions.sort()
    version = revisions[-1:][0] # get last version

    rootelem = module.search_one("container")
    rootelemarg = ""
    if rootelem and rootelem.arg:
        rootelemarg = rootelem.arg
    namespace = ""
    if rootelem and rootelem.top:
        namespace = rootelem.top.search_one("namespace").arg
    prepare = "%s" % (namespace)
    import hashlib
    print "Unhashed identifier:", prepare
    ident = hashlib.sha1(prepare).hexdigest()
    print "Identifier:", ident
    import json
    print "JSON ", json.dumps({'module': module.i_modulename, 'version': version, 'root_element': rootelemarg, 'ns': namespace, 'host': ctx.opts.nmp_hostname, 'port': ctx.opts.nmp_port, 'user': ctx.opts.nmp_username, 'identifier': ident})
    return [ident,prepare]
    

def emit_nmp(modules, fd, ctx):
    """ emit_nmp(modules, fd, depth, path, config)
    modules - list of Statements
    fd - output file descriptor
    ctx - Context of module (ctx.opts contains parameters)
    """
    if not ctx.opts.nmp_outputdir:
      print "Enter output directory for processed model by --nmp_outputdir."
      return
    print "Output directory was set to \"%s\"" % ctx.opts.nmp_outputdir

    for module in modules:
        pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(vars(module))
        namespace = ""
        ns_element = module.search_one('namespace')
        if ns_element and hasattr(ns_element, "arg"):
            namespace = ns_element.arg
        print "Namespace", namespace
        modelfile = module.pos.ref

        #Module should be placed in separate directory
        print module.i_modulename, module.keyword

	#Generate indentifier and use it as the name of a directory to store data
	model_identifier = generate_identifier(module, ctx)
	if ctx.opts.nmp_genident:
		continue #skip parsing etc
        curpathname = ctx.opts.nmp_outputdir

        create_sect_dir(curpathname)
        shutil.copy(modelfile, curpathname)
	ident = open("%s/ident-unhashed.txt" % ctx.opts.nmp_outputdir, "w")
	ident.write(model_identifier[1])
	ident.close()

        # global filter.txt for one model
        if ctx.opts.nmp_genrpc:
            rpcfilepath = curpathname + "/rpc.yin"
            rpcfile = open(rpcfilepath, "w")

        # iterate over module
        for section in module.i_children:
            if section.keyword == "container":
                print "Generate global filter.txt"
                generate_filter(curpathname, module.search("container")[0], namespace)
                #iterate over sections
                if ctx.opts.nmp_maxdepth > 0:
                    if ctx.opts.nmp_config:
                        #print "Module loop", modelname
                        #copiedsection = statement_deepcopy(section)
                        dive_into_section(section, fd, ctx, curpathname, ctx.opts.nmp_maxdepth, CONFIG_STR, namespace)
                    else:
                        dive_into_section(section, fd, ctx, curpathname, ctx.opts.nmp_maxdepth, STATE_STR, namespace)
                else:
                    save_model_part(ctx, section, curpathname, "rest")
            elif section.keyword == "rpc":
                if ctx.opts.nmp_genrpc:
                    # print RPC operations into special file
                    yin = YINPlugin()
                    yin.emit(ctx,[section], rpcfile)
            else:
                #print section.arg, section.keyword
                pass
        if ctx.opts.nmp_genrpc:
            rpcfile.close()
            postprocess_rpcfile(rpcfilepath)
    return

def postprocess_rpcfile(filepath):
        # Read content of generated rpc.yin to remove xmldoc type
        rpcfile = open(filepath, "r")
        text = rpcfile.readlines()
        rpcfile.close()
        if text:
            rpcfile = open(filepath, "w")
            rpcfile.write(text[0])
            # wrap RPC operations into root element
            rpcfile.write("<rpc-operations>\n")
            for line in text[1:]:
                rpcfile.write(line.replace('<?xml version="1.0" encoding="UTF-8"?>\n', ''))
            rpcfile.write("</rpc-operations>\n")
            rpcfile.close()


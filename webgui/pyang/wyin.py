"""Wrapped YIN output plugin for Netopeer web purpose.
Move substatements to element attributes is easier
and more useful in GUI processing."""

from xml.sax.saxutils import quoteattr
from xml.sax.saxutils import escape

import optparse
import re
import sys
import pdb

from pyang import plugin
from pyang import util
from pyang import grammar
from pyang import syntax
from pyang import statements

yin_namespace = "urn:ietf:params:xml:ns:yang:yin:1"

identityrefs = {}

def pyang_plugin_init():
    plugin.register_plugin(WYINPlugin())

class WYINPlugin(plugin.PyangPlugin):
    def add_opts(self, optparser):
        optlist = [
            optparse.make_option("--wyin-canonical",
                                 dest="wyin_canonical",
                                 action="store_true",
                                 help="Print in canonical order"),
            optparse.make_option("--wyin-pretty-strings",
                                 dest="wyin_pretty_strings",
                                 action="store_true",
                                 help="Pretty print strings"),
            optparse.make_option("--wyin-enum-delim",
                                 type="string",
                                 dest="enum_delim",
                                 default='|',
                                 help="Set delimiter of values for enumerate items."),
            ]
        g = optparser.add_option_group("wYIN output specific options")
        g.add_options(optlist)
    def setup_fmt(self, ctx):
        ctx.implicit_errors = False
    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['wyin'] = self
    def emit(self, ctx, modules, fd):
        module = modules[0]
        emit_wyin(ctx, module, fd)

def escape2xml(str):
    return str.replace("&", "&amp;").\
         replace("<", "&lt;").\
         replace(">", "&gt;").\
         replace("'", "&apos;").\
         replace('"', "&quot;")

def emit_wyin(ctx, module, fd):
    fd.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    fd.write('<%s name="%s"\n' % (module.keyword, module.arg))
    fd.write(' ' * len(module.keyword) + '  xmlns="%s"' % yin_namespace)

    prefix = module.search_one('prefix')
    if prefix is not None:
        namespace = module.search_one('namespace')
        fd.write('\n')
        fd.write(' ' * len(module.keyword))
        fd.write('  xmlns:' + prefix.arg + '=' +
                 quoteattr(namespace.arg))
    else:
        belongs_to = module.search_one('belongs-to')
        if belongs_to is not None:
            prefix = belongs_to.search_one('prefix')
            if prefix is not None:
                # read the parent module in order to find the namespace uri
                res = ctx.read_module(belongs_to.arg, extra={'no_include':True})
                if res is not None:
                    namespace = res.search_one('namespace')
                    if namespace is None or namespace.arg is None:
                        pass
                    else:
                        # success - namespace found
                        fd.write('\n')
                        fd.write(' ' * len(module.keyword))
                        fd.write('  xmlns:' + prefix.arg + '=' +
                                 quoteattr(namespace.arg))

    for imp in module.search('import'):
        prefix = imp.search_one('prefix')
        if prefix is not None:
            rev = None
            r = imp.search_one('revision-date')
            if r is not None:
                rev = r.arg
            mod = statements.modulename_to_module(module, imp.arg, rev)
            if mod is not None:
                ns = mod.search_one('namespace')
                if ns is not None:
                    fd.write('\n')
                    fd.write(' ' * len(module.keyword))
                    fd.write('  xmlns:' + prefix.arg + '=' +
                             quoteattr(ns.arg))
    fd.write('>\n')
    for ident in module.search("identity"):
        processIdentityref(ctx, ident)
    for i in module.substmts:
        if i not in module.i_children:
            emit_stmt(ctx, module, i, fd, " ", " ")
    chs = [ch for ch in module.i_children
        if ch.keyword in statements.data_definition_keywords]
    print_node(ctx, chs, module, fd)
    fd.write('</%s>\n' % module.keyword)
    #end of document

# Processing method for statements
def emit_stmt(ctx, module, stmt, fd, indent, indentstep, keys = []):
    if util.is_prefixed(stmt.raw_keyword):
        # this is an extension.  need to find its definition
        (prefix, identifier) = stmt.raw_keyword
        tag = prefix + ':' + identifier
        if stmt.i_extension is not None:
            ext_arg = stmt.i_extension.search_one('argument')
            if ext_arg is not None:
                wyin_element = ext_arg.search_one('yin-element')
                if wyin_element is not None and wyin_element.arg == 'true':
                    argname = prefix + ':' + ext_arg.arg
                    argiselem = True
                else:
                    # explicit false or no yin-element given
                    argname = ext_arg.arg
                    argiselem = False
            else:
                argiselem = False
                argname = None
        else:
            argiselem = False
            argname = None
    else:
        (argname, argiselem) = syntax.yin_map[stmt.raw_keyword]
        tag = stmt.raw_keyword

    if argiselem == False or argname is None:
        if argname is None:
            attr = ''
        else:
            attr = ' ' + argname + '=' + quoteattr(stmt.arg)
        if len(stmt.substmts) == 0:
            fd.write(indent + '<' + tag + attr + '/>\n')
        else:
            if argname and argname in "name":
                fd.write(indent + ('<%s eltype="%s"' % (stmt.arg, tag)))
            else:
                fd.write(indent + '<' + tag + attr)

            used_substmts = 0
            printed_config = False
            got_keys = False
            for s in stmt.substmts:
                if not printed_config:
                    conf_val = None
                    # find predecesor with i_config or use s' i_config
                    p = s
                    if not hasattr(p, "i_config"):
                        while (not hasattr(p, "i_config")) and (p != None):
                            p = p.parent

                    # searching finished
                    if p:
                        conf_val = p.i_config.__str__().lower()
                        if conf_val == "none":
                            conf_val = "true"
                        # write config attribute
                        fd.write(' config="%s"' % conf_val)
                        printed_config = True
                    del p

                if s.raw_keyword == "key":
                    fd.write(' key="%s"' % s.arg)
                    keys = re.findall(r'\S+', s.arg)
                    got_keys = True
                if s.raw_keyword in ["config", "type", "default", "description", "mandatory"]:
                    # already written
                    if s.raw_keyword in "config":
                        setattr(s, "i_config", s.arg)
                    else:
                        fd.write(' %s="%s"' % (s.raw_keyword, escape2xml(s.arg)))

                    if s.raw_keyword == "type":
                        if s.arg == "enumeration":
                            fd.write(' enumval="')
                            first_written = False
                            for charg in s.substmts:
                                if first_written:
                                    fd.write(ctx.opts.enum_delim)
                                else:
                                    first_written = True
                                fd.write(charg.arg)
                            fd.write('"')
                        else:
                            if s.substmts:
                                #other type "attributes"
                                for charg in s.substmts:
                                    if charg.raw_keyword == "range":
                                        fd.write(' range="' + charg.arg + '"')
                    # count used substatements to know what is the rest
                    used_substmts += 1
            # mark key elements
            if stmt.arg in keys:
                fd.write(' iskey="true"')
            else:
                fd.write(' iskey="false"')
            if not got_keys:
                keys = []

            # the rest of substatements:
            if used_substmts < stmt.substmts.__len__():
                # Need to generate pair tag
                fd.write('>\n')
                for s in stmt.substmts:
                    if s.raw_keyword not in ["config", "type",\
                    "default", "description", "mandatory",\
                    "must", "when", "key"]:
                        emit_stmt(ctx, module, s, fd, indent + indentstep,
                                  indentstep, keys)
                if argname and argname in "name":
                    fd.write(indent + ('</%s>' % stmt.arg))
                else:
                    fd.write(indent + '</' + tag + '>\n')
            else:
                # Everything from child elements was used
                fd.write('/>\n')
    else:
        fd.write(indent + '<' + tag + '>\n')
        if ctx.opts.wyin_pretty_strings:
            # since whitespace is significant in XML, the current
            # code is strictly speaking incorrect.  But w/o the whitespace,
            # it looks too ugly.
            fd.write(indent + indentstep + '<' + argname + '>\n')
            fd.write(fmt_text(indent + indentstep + indentstep, stmt.arg))
            fd.write('\n' + indent + indentstep + '</' + argname + '>\n')
        else:
            fd.write(indent + indentstep + '<' + argname + '>' + \
                       escape(stmt.arg) + \
                       '</' + argname + '>\n')
        if ctx.opts.wyin_canonical:
            substmts = grammar.sort_canonical(stmt.keyword, stmt.substmts)
        else:
            substmts = stmt.substmts
        for s in substmts:
                emit_stmt(ctx, module, s, fd, indent + indentstep, indentstep)
        fd.write(indent + '</' + tag + '>\n')

def fmt_text(indent, data):
    res = []
    for line in re.split("(\n)", escape(data)):
        if line == '':
            continue
        if line == '\n':
            res.extend(line)
        else:
            res.extend(indent + line)
    return ''.join(res)


def print_children(ctx, i_children, module, fd):
    for ch in i_children:
        print_node(ctx, ch, module, fd)

def handleEnumeration(ctx, typeelem):
    attrs = ""
    if typeelem.substmts:
        attrs += " enumval=\""
        first_written = False
        for charg in typeelem.substmts:
            if first_written:
                attrs += ctx.opts.enum_delim
            else:
                first_written = True
            attrs += charg.arg
        attrs += '"'
    return attrs

def updateIdentityrefList(ctx, basename, typename = False):
    """update identityrefs dict: add derived identity name into base"""
    global identityrefs
    if not identityrefs.has_key(basename):
        if typename != False:
            identityrefs[basename] = [typename]
        else:
            identityrefs[basename] = []
    else:
        if typename != False:
            identityrefs[basename].append(typename)

def processIdentityref(ctx, s):
    derived = False
    for childs in s.substmts:
        if childs.keyword == "base":
            updateIdentityrefList(ctx, childs.arg, s.arg)
            return
    # there is no child element <base>
    updateIdentityrefList(ctx, s.arg)

def getAttrs(ctx, s):
    """ ctx - to make settings accessible
        s - current element """
    global identityrefs
    attrs=""
    attrs += " eltype=\"%s\"" % s.keyword
    attrs += " config=\"%s\"" % s.i_config.__str__().lower()
    typeelem = get_typename(s)
    if typeelem:
        if hasattr(typeelem, "i_typedef") and typeelem.i_typedef:
            typeelem = get_typename(typeelem.i_typedef)
        typename = typeelem.arg
    else:
        typename = ''
    if typename:
        if typename == "DisplayString":
            pdb.set_trace()
        attrs += " type=\"%s\"" % typename
        if typename == "identityref":
            basename = get_basename(s.search_one('type'))
            #pdb.set_trace()
            if identityrefs.has_key(basename):
                attrs += " enumval=\""
                sep = False
                for i in identityrefs[basename]:
                    if sep:
                        attrs += "|"
                    else:
                        sep = True
                    attrs += i
    description = get_description(s)
    if description:
        attrs += " description=\"%s\"" % get_description(s)

    if s.keyword == 'leaf' and s.search_one('mandatory') is not None:
        attrs += " mandatory=\"%s\"" % s.search_one('mandatory').arg.__str__().lower()

    if hasattr(s, "i_default") and s.i_default:
        attrs += " default=\"%s\"" % s.i_default.__str__()
    if typename == "enumeration":
        attrs += handleEnumeration(ctx, typeelem)

    if hasattr(s, "i_range") and s.i_range:
        attrs += " range=\"%s\"" % s.i_range

    if s.keyword == 'list' and s.search_one('key') is not None:
        attrs += " key=\"%s\"" % re.sub('\s+', ' ', s.search_one('key').arg)

    attrs += " iskey="
    if hasattr(s, "i_is_key") and s.i_is_key:
        attrs += "\"%s\"" % s.i_is_key.__str__().lower()
    else:
        attrs += "\"false\""
    return attrs


def print_node(ctx, s, module, fd):
    if type(s) == list:
        for m in s:
            print_node(ctx,m, module, fd)
        return
    if s.i_module.i_modulename == module.i_modulename:
        name = s.arg
    else:
        name = s.i_module.i_prefix + ':' + s.arg
    if hasattr(s, 'i_children') and s.i_children:
        fd.write("<%s%s>" % (name, getAttrs(ctx, s)))
        print_children(ctx, s.i_children, module, fd)
        fd.write("</%s>\n" % (name))
    else:
        fd.write("<%s%s/>\n" % (name, getAttrs(ctx, s)))
    return

def get_typename(s):
    t = s.search_one('type')
    return t

def get_basename(s):
    t = s.search_one('base')
    if t is not None:
        return t.arg
    else:
        return ''

def get_description(s):
    t = s.search_one('description')
    if t is not None:
        return escape2xml(t.arg)
    else:
        return ''

<?xml version="1.0" standalone="yes"?>
<!--This XSLT was automatically generated from a Schematron schema.-->
<axsl:stylesheet xmlns:date="http://exslt.org/dates-and-times" xmlns:dyn="http://exslt.org/dynamic" xmlns:exsl="http://exslt.org/common" xmlns:math="http://exslt.org/math" xmlns:random="http://exslt.org/random" xmlns:regexp="http://exslt.org/regular-expressions" xmlns:set="http://exslt.org/sets" xmlns:str="http://exslt.org/strings" xmlns:axsl="http://www.w3.org/1999/XSL/Transform" xmlns:sch="http://www.ascc.net/xml/schematron" xmlns:iso="http://purl.oclc.org/dsdl/schematron" xmlns:ncserver="urn:ietf:params:xml:ns:yang:ietf-netconf-server" xmlns:nacm="urn:ietf:params:xml:ns:yang:ietf-netconf-acm" xmlns:x509c2n="urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" extension-element-prefixes="date dyn exsl math random regexp set str" version="1.0"><!--Implementers: please note that overriding process-prolog or process-root is 
    the preferred method for meta-stylesheets to use where possible. -->
<axsl:param name="archiveDirParameter"/><axsl:param name="archiveNameParameter"/><axsl:param name="fileNameParameter"/><axsl:param name="fileDirParameter"/>

<!--PHASES-->


<!--PROLOG-->
<axsl:output xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" xmlns:svrl="http://purl.oclc.org/dsdl/svrl" method="xml" omit-xml-declaration="no" standalone="yes" indent="yes"/>

<!--KEYS-->


<!--DEFAULT RULES-->


<!--MODE: SCHEMATRON-SELECT-FULL-PATH-->
<!--This mode can be used to generate an ugly though full XPath for locators-->
<axsl:template match="*" mode="schematron-select-full-path"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:template>

<!--MODE: SCHEMATRON-FULL-PATH-->
<!--This mode can be used to generate an ugly though full XPath for locators-->
<axsl:template match="*" mode="schematron-get-full-path"><axsl:apply-templates select="parent::*" mode="schematron-get-full-path"/><axsl:text>/</axsl:text><axsl:choose><axsl:when test="namespace-uri()=''"><axsl:value-of select="name()"/><axsl:variable name="p_1" select="1+    count(preceding-sibling::*[name()=name(current())])"/><axsl:if test="$p_1&gt;1 or following-sibling::*[name()=name(current())]">[<axsl:value-of select="$p_1"/>]</axsl:if></axsl:when><axsl:otherwise><axsl:text>*[local-name()='</axsl:text><axsl:value-of select="local-name()"/><axsl:text>' and namespace-uri()='</axsl:text><axsl:value-of select="namespace-uri()"/><axsl:text>']</axsl:text><axsl:variable name="p_2" select="1+   count(preceding-sibling::*[local-name()=local-name(current())])"/><axsl:if test="$p_2&gt;1 or following-sibling::*[local-name()=local-name(current())]">[<axsl:value-of select="$p_2"/>]</axsl:if></axsl:otherwise></axsl:choose></axsl:template><axsl:template match="@*" mode="schematron-get-full-path"><axsl:text>/</axsl:text><axsl:choose><axsl:when test="namespace-uri()=''">@<axsl:value-of select="name()"/></axsl:when><axsl:otherwise><axsl:text>@*[local-name()='</axsl:text><axsl:value-of select="local-name()"/><axsl:text>' and namespace-uri()='</axsl:text><axsl:value-of select="namespace-uri()"/><axsl:text>']</axsl:text></axsl:otherwise></axsl:choose></axsl:template>

<!--MODE: SCHEMATRON-FULL-PATH-2-->
<!--This mode can be used to generate prefixed XPath for humans-->
<axsl:template match="node() | @*" mode="schematron-get-full-path-2"><axsl:for-each select="ancestor-or-self::*"><axsl:text>/</axsl:text><axsl:value-of select="name(.)"/><axsl:if test="preceding-sibling::*[name(.)=name(current())]"><axsl:text>[</axsl:text><axsl:value-of select="count(preceding-sibling::*[name(.)=name(current())])+1"/><axsl:text>]</axsl:text></axsl:if></axsl:for-each><axsl:if test="not(self::*)"><axsl:text/>/@<axsl:value-of select="name(.)"/></axsl:if></axsl:template>

<!--MODE: GENERATE-ID-FROM-PATH -->
<axsl:template match="/" mode="generate-id-from-path"/><axsl:template match="text()" mode="generate-id-from-path"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:value-of select="concat('.text-', 1+count(preceding-sibling::text()), '-')"/></axsl:template><axsl:template match="comment()" mode="generate-id-from-path"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:value-of select="concat('.comment-', 1+count(preceding-sibling::comment()), '-')"/></axsl:template><axsl:template match="processing-instruction()" mode="generate-id-from-path"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:value-of select="concat('.processing-instruction-', 1+count(preceding-sibling::processing-instruction()), '-')"/></axsl:template><axsl:template match="@*" mode="generate-id-from-path"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:value-of select="concat('.@', name())"/></axsl:template><axsl:template match="*" mode="generate-id-from-path" priority="-0.5"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:text>.</axsl:text><axsl:value-of select="concat('.',name(),'-',1+count(preceding-sibling::*[name()=name(current())]),'-')"/></axsl:template><!--MODE: SCHEMATRON-FULL-PATH-3-->
<!--This mode can be used to generate prefixed XPath for humans 
	(Top-level element has index)-->
<axsl:template match="node() | @*" mode="schematron-get-full-path-3"><axsl:for-each select="ancestor-or-self::*"><axsl:text>/</axsl:text><axsl:value-of select="name(.)"/><axsl:if test="parent::*"><axsl:text>[</axsl:text><axsl:value-of select="count(preceding-sibling::*[name(.)=name(current())])+1"/><axsl:text>]</axsl:text></axsl:if></axsl:for-each><axsl:if test="not(self::*)"><axsl:text/>/@<axsl:value-of select="name(.)"/></axsl:if></axsl:template>

<!--MODE: GENERATE-ID-2 -->
<axsl:template match="/" mode="generate-id-2">U</axsl:template><axsl:template match="*" mode="generate-id-2" priority="2"><axsl:text>U</axsl:text><axsl:number level="multiple" count="*"/></axsl:template><axsl:template match="node()" mode="generate-id-2"><axsl:text>U.</axsl:text><axsl:number level="multiple" count="*"/><axsl:text>n</axsl:text><axsl:number count="node()"/></axsl:template><axsl:template match="@*" mode="generate-id-2"><axsl:text>U.</axsl:text><axsl:number level="multiple" count="*"/><axsl:text>_</axsl:text><axsl:value-of select="string-length(local-name(.))"/><axsl:text>_</axsl:text><axsl:value-of select="translate(name(),':','.')"/></axsl:template><!--Strip characters--><axsl:template match="text()" priority="-1"/>

<!--SCHEMA METADATA-->
<axsl:template match="/"><svrl:schematron-output xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" title="" schemaVersion=""><axsl:comment><axsl:value-of select="$archiveDirParameter"/>   
		 <axsl:value-of select="$archiveNameParameter"/>  
		 <axsl:value-of select="$fileNameParameter"/>  
		 <axsl:value-of select="$fileDirParameter"/></axsl:comment><svrl:ns-prefix-in-attribute-values uri="http://exslt.org/dynamic" prefix="dyn"/><svrl:ns-prefix-in-attribute-values uri="urn:ietf:params:xml:ns:yang:ietf-netconf-server" prefix="ncserver"/><svrl:ns-prefix-in-attribute-values uri="urn:ietf:params:xml:ns:yang:ietf-netconf-acm" prefix="nacm"/><svrl:ns-prefix-in-attribute-values uri="urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name" prefix="x509c2n"/><svrl:ns-prefix-in-attribute-values uri="urn:ietf:params:xml:ns:netconf:base:1.0" prefix="nc"/><svrl:active-pattern><axsl:attribute name="id">ietf-netconf-server</axsl:attribute><axsl:attribute name="name">ietf-netconf-server</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M6"/><svrl:active-pattern><axsl:attribute name="id">idm139740642191280</axsl:attribute><axsl:attribute name="name">idm139740642191280</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M7"/><svrl:active-pattern><axsl:attribute name="id">idm139740642190112</axsl:attribute><axsl:attribute name="name">idm139740642190112</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M8"/></svrl:schematron-output></axsl:template>

<!--SCHEMATRON PATTERNS-->
<axsl:param name="root" select="/nc:data"/>

<!--PATTERN ietf-netconf-server-->
<axsl:template match="text()" priority="-1" mode="M6"/><axsl:template match="@*|node()" priority="-2" mode="M6"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M6"/></axsl:template>

<!--PATTERN idm139740642191280-->


	<!--RULE -->
<axsl:template match="/nc:data/ncserver:netconf/ncserver:ssh/ncserver:listen/ncserver:interface" priority="1003" mode="M7"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/ncserver:netconf/ncserver:ssh/ncserver:listen/ncserver:interface"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::ncserver:interface[ncserver:address=current()/ncserver:address]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::ncserver:interface[ncserver:address=current()/ncserver:address]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "address"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M7"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:data/ncserver:netconf/ncserver:ssh/ncserver:call-home/ncserver:applications/ncserver:application" priority="1002" mode="M7"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/ncserver:netconf/ncserver:ssh/ncserver:call-home/ncserver:applications/ncserver:application"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::ncserver:application[ncserver:name=current()/ncserver:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::ncserver:application[ncserver:name=current()/ncserver:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M7"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:data/ncserver:netconf/ncserver:ssh/ncserver:call-home/ncserver:applications/ncserver:application/ncserver:servers/ncserver:server" priority="1001" mode="M7"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/ncserver:netconf/ncserver:ssh/ncserver:call-home/ncserver:applications/ncserver:application/ncserver:servers/ncserver:server"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::ncserver:server[ncserver:address=current()/ncserver:address]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::ncserver:server[ncserver:address=current()/ncserver:address]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "address"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M7"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:data/ncserver:netconf/ncserver:ssh/ncserver:call-home/ncserver:applications/ncserver:application/ncserver:host-keys/ncserver:host-key" priority="1000" mode="M7"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/ncserver:netconf/ncserver:ssh/ncserver:call-home/ncserver:applications/ncserver:application/ncserver:host-keys/ncserver:host-key"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::ncserver:host-key[ncserver:name=current()/ncserver:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::ncserver:host-key[ncserver:name=current()/ncserver:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M7"/></axsl:template><axsl:template match="text()" priority="-1" mode="M7"/><axsl:template match="@*|node()" priority="-2" mode="M7"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M7"/></axsl:template>

<!--PATTERN idm139740642190112-->


	<!--RULE -->
<axsl:template match="/nc:data/ncserver:netconf/ncserver:tls/ncserver:listen/ncserver:interface" priority="1001" mode="M8"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/ncserver:netconf/ncserver:tls/ncserver:listen/ncserver:interface"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::ncserver:interface[ncserver:address=current()/ncserver:address]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::ncserver:interface[ncserver:address=current()/ncserver:address]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "address"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M8"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:data/ncserver:netconf/ncserver:tls/ncserver:psk-maps/ncserver:psk-map" priority="1000" mode="M8"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/ncserver:netconf/ncserver:tls/ncserver:psk-maps/ncserver:psk-map"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::ncserver:psk-map[ncserver:psk-identity=current()/ncserver:psk-identity]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::ncserver:psk-map[ncserver:psk-identity=current()/ncserver:psk-identity]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "psk-identity"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M8"/></axsl:template><axsl:template match="text()" priority="-1" mode="M8"/><axsl:template match="@*|node()" priority="-2" mode="M8"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M8"/></axsl:template></axsl:stylesheet>

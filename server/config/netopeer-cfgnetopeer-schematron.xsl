<?xml version="1.0" standalone="yes"?>
<!--This XSLT was automatically generated from a Schematron schema.-->
<axsl:stylesheet xmlns:date="http://exslt.org/dates-and-times" xmlns:dyn="http://exslt.org/dynamic" xmlns:exsl="http://exslt.org/common" xmlns:math="http://exslt.org/math" xmlns:random="http://exslt.org/random" xmlns:regexp="http://exslt.org/regular-expressions" xmlns:set="http://exslt.org/sets" xmlns:str="http://exslt.org/strings" xmlns:axsl="http://www.w3.org/1999/XSL/Transform" xmlns:sch="http://www.ascc.net/xml/schematron" xmlns:iso="http://purl.oclc.org/dsdl/schematron" xmlns:x509c2n="urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name" xmlns:cfgnetopeer="urn:cesnet:tmc:netopeer:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" extension-element-prefixes="date dyn exsl math random regexp set str" version="1.0"><!--Implementers: please note that overriding process-prolog or process-root is 
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
		 <axsl:value-of select="$fileDirParameter"/></axsl:comment><svrl:ns-prefix-in-attribute-values uri="http://exslt.org/dynamic" prefix="dyn"/><svrl:ns-prefix-in-attribute-values uri="urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name" prefix="x509c2n"/><svrl:ns-prefix-in-attribute-values uri="urn:cesnet:tmc:netopeer:1.0" prefix="cfgnetopeer"/><svrl:ns-prefix-in-attribute-values uri="urn:ietf:params:xml:ns:netconf:base:1.0" prefix="nc"/><svrl:active-pattern><axsl:attribute name="id">netopeer-cfgnetopeer</axsl:attribute><axsl:attribute name="name">netopeer-cfgnetopeer</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M5"/><svrl:active-pattern><axsl:attribute name="id">idm140262944304080</axsl:attribute><axsl:attribute name="name">idm140262944304080</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M6"/></svrl:schematron-output></axsl:template>

<!--SCHEMATRON PATTERNS-->
<axsl:param name="root" select="/nc:data"/>

<!--PATTERN netopeer-cfgnetopeer-->


	<!--RULE -->
<axsl:template match="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:ssh/cfgnetopeer:client-auth-keys/cfgnetopeer:client-auth-key" priority="1003" mode="M5"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:ssh/cfgnetopeer:client-auth-keys/cfgnetopeer:client-auth-key"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::cfgnetopeer:client-auth-key[cfgnetopeer:path=current()/cfgnetopeer:path]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::cfgnetopeer:client-auth-key[cfgnetopeer:path=current()/cfgnetopeer:path]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "cfgnetopeer:path"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M5"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:tls/cfgnetopeer:trusted-ca-certs/cfgnetopeer:trusted-ca-cert" priority="1002" mode="M5"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:tls/cfgnetopeer:trusted-ca-certs/cfgnetopeer:trusted-ca-cert"/>

		<!--REPORT -->
<axsl:if test=". = preceding-sibling::cfgnetopeer:trusted-ca-cert"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test=". = preceding-sibling::cfgnetopeer:trusted-ca-cert"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate leaf-list entry "<axsl:text/><axsl:value-of select="."/><axsl:text/>".</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M5"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:tls/cfgnetopeer:trusted-client-certs/cfgnetopeer:trusted-client-cert" priority="1001" mode="M5"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:tls/cfgnetopeer:trusted-client-certs/cfgnetopeer:trusted-client-cert"/>

		<!--REPORT -->
<axsl:if test=". = preceding-sibling::cfgnetopeer:trusted-client-cert"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test=". = preceding-sibling::cfgnetopeer:trusted-client-cert"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate leaf-list entry "<axsl:text/><axsl:value-of select="."/><axsl:text/>".</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M5"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:modules/cfgnetopeer:module" priority="1000" mode="M5"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:modules/cfgnetopeer:module"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::cfgnetopeer:module[cfgnetopeer:name=current()/cfgnetopeer:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::cfgnetopeer:module[cfgnetopeer:name=current()/cfgnetopeer:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "cfgnetopeer:name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M5"/></axsl:template><axsl:template match="text()" priority="-1" mode="M5"/><axsl:template match="@*|node()" priority="-2" mode="M5"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M5"/></axsl:template>

<!--PATTERN idm140262944304080-->


	<!--RULE -->
<axsl:template match="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:tls/cfgnetopeer:cert-maps/cfgnetopeer:cert-to-name" priority="1001" mode="M6"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:tls/cfgnetopeer:cert-maps/cfgnetopeer:cert-to-name"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::cfgnetopeer:cert-to-name[cfgnetopeer:id=current()/cfgnetopeer:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::cfgnetopeer:cert-to-name[cfgnetopeer:id=current()/cfgnetopeer:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M6"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:tls/cfgnetopeer:cert-maps/cfgnetopeer:cert-to-name/cfgnetopeer:name" priority="1000" mode="M6"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:data/cfgnetopeer:netopeer/cfgnetopeer:tls/cfgnetopeer:cert-maps/cfgnetopeer:cert-to-name/cfgnetopeer:name"/>

		<!--ASSERT -->
<axsl:choose><axsl:when test="ancestor-or-self::*[processing-instruction('dsrl')] or (../cfgnetopeer:map-type = 'x509c2n:specified')"/><axsl:otherwise><svrl:failed-assert xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="ancestor-or-self::*[processing-instruction('dsrl')] or (../cfgnetopeer:map-type = 'x509c2n:specified')"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Node "name" is only valid when "../cfgnetopeer:map-type = 'x509c2n:specified'"</svrl:text></svrl:failed-assert></axsl:otherwise></axsl:choose><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M6"/></axsl:template><axsl:template match="text()" priority="-1" mode="M6"/><axsl:template match="@*|node()" priority="-2" mode="M6"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M6"/></axsl:template></axsl:stylesheet>

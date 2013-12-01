<?php
/*!
 * \file phpmynetconf.php
 * \brief NETCONF PHP gateway for Apache module of Netopeer
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2012
 */
/*
 * Copyright (C) 2011-2012 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

/* Enumeration of Message type (taken from mod_netconf.c) */
class MsgType {
	const REPLY_OK		= 0;
	const REPLY_DATA	= 1;
	const REPLY_ERROR	= 2;
	const REPLY_INFO	= 3;
	const MSG_CONNECT	= 4;
	const MSG_DISCONNECT	= 5;
	const MSG_GET		= 6;
	const MSG_GETCONFIG	= 7;
	const MSG_EDITCONFIG	= 8;
	const MSG_COPYCONFIG	= 9;
	const MSG_DELETECONFIG  = 10;
	const MSG_LOCK		= 11;
	const MSG_UNLOCK	= 12;
	const MSG_KILL		= 13;
	const MSG_INFO		= 14;
	const MSG_GENERIC	= 15;
};

function unwrap_rfc6242($message)
{
	$response = "";
	if ($message == "") {
		return $response;
	}
	$chunks = explode("\n#", $message);
	$numchunks = sizeof($chunks);
	$i = 0;
	if ($numchunks > 0) {
		do {
			if ($i == 0 && $chunks[$i++] != "") {
				/* something is wrong, message should start by '\n#'
				 */
				echo "Wrong message format, it is not according to RFC6242 (starting with \\n#).";
				echo var_export($message, true);
				throw new \ErrorException("Wrong message format, it is not according to RFC6242 (starting with \\n#).");
			}
			if ($i >= $numchunks) {
				echo "Malformed message (RFC6242) - Bad amount of parts.";
				echo var_export($message, true);
				/* echo "chunk length<br>\n"; */
				throw new \ErrorException("Malformed message (RFC6242) - Bad amount of parts.");
			}
			$len = 0;
			sscanf($chunks[$i], "%i", $len);

			/* echo "chunk data<br>\n"; */
			$nl = strpos($chunks[$i], "\n");
			if ($nl === false) {
				echo "Malformed message (RFC6242) - There is no \\n after chunk-data size.";
				echo var_export($message, true);
				throw new \ErrorException("Malformed message (RFC6242) - There is no \\n after chunk-data size.");
			}
			$data = substr($chunks[$i], $nl + 1);
			$realsize = strlen($data);
			if ($realsize != $len) {
				echo "Chunk $i has the length $realsize instead of $len.";
				echo var_export($message, true);
				throw new \ErrorException("Chunk $i has the length $realsize instead of $len.");
			}
			$response .= $data;
			$i++;
			if ($chunks[$i][0] == '#') {
				/* ending part */
				break;
			}
		} while ($i<$numchunks);
	}

	return $response;
}

function write2socket(&$sock, $message)
{
	$final_message = sprintf("\n#%d\n%s\n##\n", strlen($message), $message);
	fwrite($sock, $final_message);
}
/**
  \brief Read response from socket
  \param[in,out] $sock socket descriptor
  \return trimmed string that was read
 */
function readnetconf2(&$sock)
{
	$start = microtime(true);
	$response = "";
	do {
		$tmp = "";
		$tmp = fread($sock, 4096);
		if ($tmp != "") {
			$response .= $tmp;
		}
		if (strlen($tmp) < 4096) {
			break;
		}
	} while ($tmp != "");
	$res = "";
	try {
		$res = unwrap_rfc6242($response);
	} catch (\Exception $e) {
		echo $e;
		return "";
	}
	echo "readnetconf elapsed time: ".(microtime(true) - $start);
	return $res;
}
function readnetconf(&$sock) {
	stream_set_blocking($sock, 1);
	//stream_set_timeout($sock, 1, 100);
//$start = microtime(true);
	$response = "";
	$tmp = "";
	$tmp = fread($sock, 1024);
	if ($tmp === false) {
		$this->container->get('request')->getSession()->setFlash($this->flashState .' error', "Reading failure.");
	}

	$response = $tmp;
	// message is wrapped in "\n#strlen($m)\n$m\n##\n"
	// get size:
	$lines = explode("\n", $tmp);
	if (sizeof($lines >= 2)) {
		$size = strlen($lines[0]) + 1 + strlen($lines[1]) + 1;
		$size += intval(substr($lines[1], 1)) + 5;
	}

	while (strlen($response) < $size) {
		$tmp = "";
		$tmp = fread($sock, $size - strlen($response));
		if ($tmp === false) {
			#$this->container->get('request')->getSession()->setFlash($this->flashState .' error', "Reading failure.");
			echo "reading failure";
			die();
		}
		$response .= $tmp;
		echo strlen($response) ."/". $size ."\n";
	}
	$status = stream_get_meta_data($sock);
	if (!$response && $status["timed_out"] == true) {
		#$this->container->get('request')->getSession()->setFlash($this->flashState .' error', "Reached timeout for reading response.");
		echo "Reached timeout for reading response.";
	}
	/* "unchunk" frames (RFC6242) */
	try {
		$response = unwrap_rfc6242($response);
	} catch (\ErrorException $e) {
		#$this->container->get('request')->getSession()->setFlash($this->flashState .' error', "Could not read NetConf. Error: ".$e->getMessage());
		echo "unwrap exception";
		return 1;
	}
//echo "readnetconf time consumed: ". (microtime(true) - $start);

	return trim($response);
}

function printJsonError() {
	switch (json_last_error()) {
		case JSON_ERROR_NONE:
			echo 'No errors';
			break;
		case JSON_ERROR_DEPTH:
			echo 'Maximum stack depth exceeded';
			break;
		case JSON_ERROR_STATE_MISMATCH:
			echo 'Underflow or the modes mismatch';
			break;
		case JSON_ERROR_CTRL_CHAR:
			echo 'Unexpected control character found';
			break;
		case JSON_ERROR_SYNTAX:
			echo 'Syntax error, malformed JSON';
			break;
		case JSON_ERROR_UTF8:
			echo 'Malformed UTF-8 characters, possibly incorrectly encoded';
			break;
		default:
			echo 'Unknown error';
			break;
	}
}

/**
  \brief Prints formatted XML
 */
function printxml($string)
{
	$xmlObj = simplexml_load_string("<rootnode>".str_replace('<?xml version="1.0" encoding="UTF-8"?>', "", $string)."</rootnode>");
	echo("<pre>".htmlspecialchars($xmlObj->asXML())."</pre>");
}

/**
 \param[in,out] $sock socket descriptor
 \return 0 on success
*/
function handle_connect(&$sock)
{
	$capabilities = explode("\n", trim(str_replace("\r", "", $_REQUEST["capab"])));
	$connect = json_encode(array("type" => MsgType::MSG_CONNECT,
	"host" => $_REQUEST["host"],
	"port" => 22,
	"user" => $_REQUEST["user"],
	"pass" => $_REQUEST["pass"],
	"capabilities" => $capabilities,
	));
	write2socket($sock, $connect);
	$response = readnetconf($sock);
	$decoded = json_decode($response, true);
	echo "<h2>CONNECT</h2>";
	if ($decoded && ($decoded["type"] == MsgType::REPLY_OK)) {
		$sessionkey = $decoded["session"];
		if (!isset($_SESSION["keys"])) {
			$_SESSION["keys"] = array("$sessionkey");
		} else {
			$_SESSION["keys"][] = $sessionkey;
		}
		if (!isset($_SESSION["hosts"])) {
			$_SESSION["hosts"] = array($_REQUEST["host"]);
		} else {
			$_SESSION["hosts"][] = $_REQUEST["host"];
		}
		echo "Successfully connected.";
		return 0;
	} else {
		echo "Could not connect.<br>";
		echo "Result: ". var_export($decoded, true);
		return 1;
	}
}

/**
 \return 0 on success
 */
function check_logged_keys()
{
	if (!isset($_SESSION["keys"])) {
		echo "Not logged in.";
		return 1;
	}
	if (!isset($_REQUEST["key"])) {
		echo "No Index of key.";
		return 1;
	}
	if (!isset($_SESSION["keys"][$_REQUEST["key"]])) {
		echo "Bad Index of key.";
		return 1;
	}
	return 0;
}

/**
 \param[in,out] $sock socket descriptor
 \param[in] $params array of values for mod_netconf (type, params...)
 \return array - response from mod_netconf
*/
function execute_operation(&$sock, $params)
{
	$operation = json_encode($params);
	write2socket($sock, $operation);
	$response = readnetconf($sock);
	return json_decode($response, true);
}

/**
 \param[in,out] $sock socket descriptor
 \return 0 on success
*/
function handle_get(&$sock)
{
	if (check_logged_keys() != 0) {
		return 1;
	}
	$sessionkey = $_SESSION["keys"][$_REQUEST["key"]];

	$params = array("type" => MsgType::MSG_GET,
			"session" => $sessionkey,
			"source" => "running");
	if (isset($_REQUEST["filter"]) && $_REQUEST["filter"] != "") {
		$params["filter"] = $_REQUEST["filter"];
	}
	$decoded = execute_operation($sock, $params);

	echo "<h2>GET</h2>";
	printxml($decoded["data"]);
}

/**
 \param[in,out] $sock socket descriptor
 \return 0 on success
*/
function handle_getconfig(&$sock)
{
	if (check_logged_keys() != 0) {
		return 1;
	}
	$sessionkey = $_SESSION["keys"][$_REQUEST["key"]];
	$params = array("type" => MsgType::MSG_GETCONFIG,
			"session" => $sessionkey,
			"source" => (isset($_REQUEST["source"])?$_REQUEST["source"]:"running"));
	if (isset($_REQUEST["filter"]) && $_REQUEST["filter"] != "") {
		$params["filter"] = $_REQUEST["filter"];
	}
	$decoded = execute_operation($sock, $params);

	echo "<h2>GET-CONFIG</h2>";
	printxml($decoded["data"]);
	return 0;
}

/**
 \param[in,out] $sock socket descriptor
 \return 0 on success
*/
function handle_editconfig(&$sock)
{
	if (check_logged_keys() != 0) {
		return 1;
	}
	$sessionkey = $_SESSION["keys"][$_REQUEST["key"]];
	/* execute get-config */
	$decoded = execute_operation($sock,
		array("type" => MsgType::MSG_GETCONFIG,
		"session" => $sessionkey,
		"source" => "running"));

	/* apply changes */
	$oldtree = $decoded["data"];
	var_dump($oldtree);
	echo "<br><br><br>";
	$newtree = simplexml_load_string("<rootnode>".str_replace('<?xml version="1.0" encoding="UTF-8"?>', "", $oldtree)."</rootnode>");
	echo "<br><br><br>";
	var_dump($newtree->{'comet-testers'}->{'comet-tester'}->statistics->enabled);
	//return 0;
	$newtree->{'comet-testers'}->{'comet-tester'}->statistics->enabled = "false";
	var_dump($newtree->{'comet-testers'}->{'comet-tester'}->statistics->enabled);
	$config = "";
	foreach ($newtree as $ch) {
		$config .= $ch->asXML();
	}
	/* copy-config to store new values */
	$params = array("type" => MsgType::MSG_EDITCONFIG,
			"session" => $sessionkey,
			"target" => "running",
			"config" => $config);
	print_r($params);
	$decoded = execute_operation($sock, $params);

	echo "<h2>EDIT-CONFIG</h2>";
	var_dump($decoded);
	return 0;
}

function handle_copyconfig(&$sock)
{
	$sessionkey = $_SESSION["keys"][$_REQUEST["key"]];
	if (isset($_REQUEST["config"]) && $_REQUEST["config"] != '') {
		$config = $_REQUEST["config"];
		var_dump($config);
		$params = array("type" => MsgType::MSG_COPYCONFIG,
			"session" => $sessionkey,
			"target" => "running",
			"config" => $config);
		$decoded = execute_operation($sock, $params);
		var_dump($decoded);
	} else {
		echo "No config was sent";
	}
}

/**
 \param[in,out] $sock socket descriptor
 \return 0 on success
*/
function handle_disconnect(&$sock)
{
	if (check_logged_keys() != 0) {
		return 1;
	}
	$sessionkey = $_SESSION["keys"][$_REQUEST["key"]];
	$decoded = execute_operation($sock,
		array(	"type" => MsgType::MSG_DISCONNECT,
			"session" => $sessionkey));
	echo "<h2>Disconnect</h2>";
	if ($decoded["type"] == MsgType::REPLY_OK) {
		echo "Successfully disconnected.";
	} else {
		echo "Error occured.";
		var_dump($decoded);
	}
	unset($_SESSION["keys"][$_REQUEST["key"]]);
	unset($_SESSION["hosts"][$_REQUEST["key"]]);
	$_SESSION["keys"] = array_values($_SESSION["keys"]);
	$_SESSION["hosts"] = array_values($_SESSION["hosts"]);
}

/* main part of script */
session_start();

/* create connection with socket */
if (isset($_REQUEST["getconfig"]) || (isset($_REQUEST["command"]))) {
	$errno = 0;
	$errstr = "";
	$sock = fsockopen('unix:///tmp/mod_netconf.sock', NULL, $errno, $errstr);
	if ($errno != 0) {
		echo "Could not connect to socket.";
		echo "$errstr";
		return 1;
	}
	stream_set_timeout($sock, 1, 100);
}

/* pseudo-AJAX response of get-config running */
if (isset($_REQUEST["getconfig"])) {
	if (check_logged_keys() != 0) {
		return 1;
	}
	$sessionkey = $_SESSION["keys"][$_REQUEST["key"]];
	$params = array("type" => MsgType::MSG_GETCONFIG,
			"session" => $sessionkey,
			"source" => "running");
	$decoded = execute_operation($sock, $params);
	echo $decoded["data"];
	/* end script return only data */
	exit(0);
}


/* print mainpage */
echo "<html><head><title>phpMyNetconf</title><body>";
if (!isset($_REQUEST["command"])) {
	echo "<h2>Connect to new NETCONF server</h2>
	<form action='?' method='POST'>
	<input type='hidden' name='command' value='connect'>
	<label for='host'>Hostname:</label><input type='text' name='host'><br>
	<label for='user'>Username:</label><input type='text' name='user'><br>
	<label for='pass'>Password:</label><input type='password' name='pass'><br>
	<label for='capab'>Capabilities:</label><br><textarea name='capab' rows=10 cols=100>
urn:ietf:params:netconf:base:1.0
urn:ietf:params:netconf:base:1.1
urn:ietf:params:netconf:capability:startup:1.0
urn:ietf:params:netconf:capability:writable-running:1.0
urn:ietf:params:netconf:capability:candidate:1.0
urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=explicit&amp;also-supported=report-all,report-all-tagged,trim,explicit
urn:cesnet:tmc:comet:1.0
urn:cesnet:tmc:combo:1.0
urn:cesnet:tmc:hanicprobe:1.0
</textarea><br>
	<input type='submit' value='Login'>
	</form>";
	if (isset($_SESSION["keys"]) && sizeof($_SESSION["keys"])) {
		echo "<h2>Already connected nodes</h2>";
		$keys = $_SESSION["keys"];
		$i = 0;
		foreach ($keys as $k) {
			echo "$i ".$_SESSION["hosts"][$i]."
<form action='?' method='GET'>
<input type='hidden' name='command' value='get'>
<input type='hidden' name='key' value='$i'>
<label for='get-filter'>Filter:</label><input type='text' name='filter'>
<input type='submit' value='Execute Get'></form>
<form action='?' method='GET'>
<input type='hidden' name='command' value='getconfig'>
<input type='hidden' name='key' value='$i'>
<label for='get-filter'>Filter:</label><input type='text' name='filter'>
<select name='source'><option value='running'>Running</option>
<option value='startup'>Start-up</option>
<option value='candidate'>Candidate</option></select>
<input type='submit' value='Execute Get-config'></form>
<!--<form action='?' method='GET'>
<input type='hidden' name='command' value='editconfig'>
<input type='hidden' name='key' value='$i'>
<label for='edit-element'>Element name:</label><input type='text' name='element'>
<label for='edit-value'>Value:</label><input type='text' name='newval'>
<input type='submit' value='Execute Edit-config'>
</form>-->
<form action='?' method='POST'>
<input type='hidden' name='command' value='copyconfig'>
<input type='hidden' name='key' value='$i'>
<textarea name='config' id='configdata$i' cols=40 rows=10></textarea>
<input type='submit' value='Rewrite running config'> (copy-config)
</form>
<a href='?command=disconnect&amp;key=$i'><button>disconnect</button></a><br>
<script type='text/javascript'>
xmlHttp = new XMLHttpRequest();
xmlHttp.open( 'GET', '?key=$i&getconfig', false );
xmlHttp.send( null );
document.getElementById('configdata$i').value=xmlHttp.responseText;
</script>";
			$i++;
		}
	}
	exit(0);
}

/* handle commands */
if (isset($_REQUEST["command"])) {
	echo "<a href='?'>Back</a>";

	if ($_REQUEST["command"] === "connect") {
		handle_connect($sock);
	} else if ($_REQUEST["command"] === "copyconfig") {
		handle_copyconfig($sock);
	} else if ($_REQUEST["command"] === "editconfig") {
		handle_editconfig($sock);
	} else if ($_REQUEST["command"] === "get") {
		handle_get($sock);
	} else if ($_REQUEST["command"] === "getconfig") {
		handle_getconfig($sock);
	} else if ($_REQUEST["command"] === "disconnect") {
		handle_disconnect($sock);
	} else {
		printf("Not implemented yet. (%s)", $_REQUEST["command"]);
	}
	fclose($sock);
}
echo "</body></html>";


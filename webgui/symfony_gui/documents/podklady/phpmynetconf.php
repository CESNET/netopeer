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

/**
  \brief Read response from socket
  \param[in,out] $sock socket descriptor
  \return trimmed string that was read
 */
function readnetconf(&$sock)
{
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
	$connect = json_encode(array("type" => MsgType::MSG_CONNECT,
	"host" => $_REQUEST["host"],
	"port" => 22,
	"user" => $_REQUEST["user"],
	"pass" => $_REQUEST["pass"]
	));
	fwrite($sock, $connect);
	$response = readnetconf($sock);
	$decoded = json_decode($response, true);
	echo "<h2>CONNECT</h2>";
	if ($decoded["type"] == MsgType::REPLY_OK) {
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
		echo "Could not connect.";
		var_dump($decoded);
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
	fwrite($sock, $operation);
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

	$decoded = execute_operation($sock,
		array(	"type" => MsgType::MSG_GET,
			"session" => $sessionkey,
			"source" => "running"));

	echo "<h2>GET-CONFIG</h2>";
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
	$decoded = execute_operation($sock,
		array(	"type" => MsgType::MSG_GETCONFIG,
			"session" => $sessionkey,
			"source" => "running"));

	echo "<h2>GET-CONFIG</h2>";
	printxml($decoded["data"]);
	return 0;
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

if (!isset($_REQUEST["command"])) {
	echo "<h2>Connect to new NETCONF server</h2>
	<form action='?' method='POST'>
	<input type='hidden' name='command' value='connect'>
	<label for='host'>Hostname:</label><input type='text' name='host'><br>
	<label for='user'>Username:</label><input type='text' name='user'><br>
	<label for='pass'>Password:</label><input type='password' name='pass'><br>
	<input type='submit' value='Login'>
	</form>";
// pavl√k jan
	if (isset($_SESSION["keys"])) {
		echo "<h2>Already connected nodes</h2>";
		$keys = $_SESSION["keys"];
		$i = 0;
		foreach ($keys as $k) {
			echo "$i ".$_SESSION["hosts"][$i]." <a href='?command=get&amp;key=$i'>get</a> <a href='?command=getconfig&amp;key=$i'>get-config</a> <a href='?command=disconnect&amp;key=$i'>disconnect</a><br>";
			$i++;
		}
	}
	exit(0);
}

if (isset($_REQUEST["command"])) {
	$errno = 0;
	$errstr = "";
	$sock = fsockopen('unix:///tmp/mod_netconf.sock', NULL, $errno, $errstr);
	if ($errno != 0) {
		echo "Could not connect to socket.";
		echo "$errstr";
		return 1;
	}
	stream_set_timeout($sock, 1, 100);
	echo "<a href='?'>Back</a>";

	if ($_REQUEST["command"] === "connect") {
		handle_connect($sock);
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
	exit(0);
}



<?php
/**
 * File with Entity of connected device.
 *
 * Holds all information about connected device, which
 * will be stored in session array after successful connection.
 *
 * @author David Alexa <alexa.david@me.com>
 *
 * Copyright (C) 2012-2013 CESNET
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
 */
namespace FIT\NetopeerBundle\Entity;

/**
 * Class with Entity of connected device.
 */
class ConnectionSession {
	/**
	 * @var string time of connection start
	 */
	public $time;

	/**
	 * @var string identification key of connection
	 */
	public $hash;

	/**
	 * @var string target hostname
	 */
	public $host;

	/**
	 * @var int target port
	 */
	public $port;

	/**
	 * @var string logged username
	 */
	public $user;

	/**
	 * @var bool locked by us
	 */
	public $locked;

	/**
	 * @var string  selected data store
	 */
	public $currentDatastore;

	/**
	 * @var string session info
	 */
	public $sessionStatus = "";

	/**
	 * Creates new instance and fill in all class variables except of sessionStatus.
	 *
	 * @param string $session_hash  identification key of connection
	 * @param string $host          target hostname
	 * @param int    $port          target port
	 * @param string $user          logged username
	 */
	function __construct($session_hash, $host, $port, $user)
	{
		$this->hash = $session_hash;
		$this->host = $host;
		$this->port = $port;
		$this->user = $user;
		$newtime = new \DateTime();
		$this->time = $newtime->format("d.m.Y H:i:s");
		$this->locked = array();
		$this->setCurrentDatastore("running");
	}

	/**
	 * toggles datastore lock
	 *
	 * @param string $datastore   if not defined, current data store is used
	 */
	public function toggleLockOfDatastore($datastore = "currentDatastore") {
		if ($datastore === "currentDatastore") {
			$datastore = $this->getCurrentDatastore();
		}
		if (!isset($this->locked[$datastore])) {
			$this->locked[$datastore] = false;
		}
		$this->locked[$datastore] = !$this->locked[$datastore];
	}

	/**
	 * returns datastore lock status
	 *
	 * @param string $datastore   if not defined, current data store is used
	 * @return bool
	 */
	public function getLockForDatastore($datastore = "currentDatastore") {
		if ($datastore === "currentDatastore") {
			$datastore = $this->getCurrentDatastore();
		}
		if (!isset($this->locked[$datastore])) {
			$this->locked[$datastore] = false;
		}
		return $this->locked[$datastore];
	}

	/**
	 * @param string $datastore    datastore identifier
	 */
	public function setCurrentDatastore($datastore) {
		$this->currentDatastore = $datastore;
	}

	/**
	 * @return string   current datastore identifier, which is used
	 */
	public function getCurrentDatastore() {
		return $this->currentDatastore;
	}
}

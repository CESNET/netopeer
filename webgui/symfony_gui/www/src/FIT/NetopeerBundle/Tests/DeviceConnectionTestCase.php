<?php
/**
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
require_once 'DefaultTestCase.php';

/**
 * Tests connection to the device, logout and using history
 * of connected devices.
 */
class DeviceConnectionTestCase extends DefaultTestCase
{
	/**
	 * test connection to the device, also with handling
	 * history and profiles of connected devices,
	 * and logout from device
	 *
	 * @throws Exception
	 */
	public function testDeviceConnection()
	{
		$this->open(self::$browserUrl);

		// login to webGUI
		if ($this->loginCorrectly()) {
			$this->connectToDevice();

			sleep(3);

			// connect to device from history
			$this->click("css=a.device-item");

			sleep(3);

			// type password (other credentials are from history)
			$this->type("id=form_password", self::$login['pass']);
			$this->click("css=input[type=\"submit\"]");
			$this->waitForAjaxPageToLoad("30000");
			try {
				$this->assertFalse($this->isTextPresent("Could not connect"));
			} catch (PHPUnit_Framework_AssertionFailedError $e) {
				throw new \Exception('Could not connect to server for second time.');
			}

			$this->isTextPresent("Form has been filled up correctly.");
			sleep(4);

			// add device from history to profiles of connected devices
			$this->click("//div[@id='block--historyOfConnectedDevices']/a/span[2]");
			$this->isTextPresent("Device has been");

			sleep(2);
			// delete device from history of connected devices
			$this->click("//div[@id='block--profilesOfConnectedDevices']/a/span");
			sleep(2);
			$this->isTextPresent("Device has been");

			// connect once more time to device from history
			$this->click("css=a.device-item");
			$this->type("id=form_password", self::$login['pass']);
			$this->click("css=input[type=\"submit\"]");
			$this->waitForAjaxPageToLoad("30000");
			try {
				$this->assertFalse($this->isTextPresent("Could not connect"));
			} catch (PHPUnit_Framework_AssertionFailedError $e) {
				throw new \Exception('Could not connect to server from history.');
			}

			// disconnect from devices
			for ($i = 0; $i < 2; $i++) {
				$this->click("link=Disconnect");
				$this->waitForAjaxPageToLoad("30000");
//				$this->assertTrue($this->isTextPresent("Successfully disconnected."), "Could not disconnect from device.");
//				TODO: opravit zobrazeni hlasky
			}

			$this->assertTrue($this->isTextPresent('You are not connected to any server'), "Did not disconnet from all devices");

			sleep(2);

			// delete device from history
			$this->click("//div[@id='block--historyOfConnectedDevices']/a/span");
			sleep(2);
			$this->isTextPresent("Device has been");
		}
	}
}
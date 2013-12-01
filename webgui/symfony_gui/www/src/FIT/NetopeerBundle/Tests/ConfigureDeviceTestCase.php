<?php
/**
 * Configure device tests
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
require_once 'DefaultTestCase.php';

/**
 * Configure device test
 *
 * This class tests creating links and dividing them into top menu, left menu,
 * handling edit config (create, duplicate, delete node), lock and unlock device,
 * turning on and off double column layout.
 */
class ConfigureDeviceTestCase extends DefaultTestCase
{
	/**
	 * Testing device configuration
	 */
	public function testConfigureDevice() {
		$this->open(self::$browserUrl);

		// login to webGUI
		if ($this->loginCorrectly()) {
			$this->connectToDevice();
			for ($second = 0; ; $second++) {
				if ($second >= 60) $this->fail("Could not process get-schema. Connection timeout.");
				try {
					if ($this->isTextPresent("Configure device")) break;
				} catch (Exception $e) {}
				sleep(1);
			}


			$this->connectToDevice();
			for ($second = 0; ; $second++) {
				if ($second >= 60) $this->fail("Could not process get-schema. Connection timeout.");
				try {
					if ($this->isTextPresent("Configure device")) break;
				} catch (Exception $e) {}
				sleep(1);
			}

			$this->click("link=Configure device");
			$this->waitForAjaxPageToLoad("30000");

			/*
			// TODO: opravit zamykani/odemykani
			$this->handleLockAndUnlock();
			*/

			$this->checkColumnsChange();
			$this->assertTrue($this->isElementPresent("css=.tooltip"), "Tooltip not presented");

			// check, if link All is presented
			$this->assertTrue($this->isElementPresent("link=All"), "No module ALL exists.");
			$this->click("link=All");
			$this->waitForAjaxPageToLoad("30000");

			$this->checkColumnsChange();

			$this->click("link=Netopeer");
			$this->waitForAjaxPageToLoad("30000");

			try {
				$this->assertEquals("on", $this->getValue("name=configDataForm[module-allowed_-*-*?1!-*?1!-*?2!]"), "Netopeer module is not on???");
			} catch (PHPUnit_Framework_AssertionFailedError $e) {
				array_push($this->verificationErrors, $e->toString());
			}
			$this->click("name=configDataForm[module-allowed_-*-*?1!-*?2!-*?2!]");
			$this->click("css=input[type=\"submit\"]");
			$this->waitForAjaxPageToLoad("30000");
			$this->checkPageError();

			$this->assertTrue($this->isElementPresent("css=div.alert.error"), "Alert with Could not turn on Combo should appear");


			if ($this->isTextPresent("Hanic probes")) {
				$this->click("link=Hanic probes");
				$this->waitForAjaxPageToLoad("30000");
				$this->checkPageError();

				if ($this->isTextPresent("Exporters")) {
					$this->click("link=Exporters");
					$this->checkPageError();

					$this->click("xpath=(//img[@alt='Add sibling'])[2]");
					for ($second = 0; ; $second++) {
						if ($second >= 60) $this->fail("Could not create form for adding sibling.");
						try {
							if ($this->isElementPresent("css=.generatedForm")) break;
						} catch (Exception $e) {}
						sleep(1);
					}


					$this->waitForAjaxPageToLoad("30000");
					$this->click("xpath=(//img[@alt='Add sibling'])[2]");
					$this->type("name=duplicatedNodeForm[id_-*-*?1!-*?2!-*?1!-*?1!]", "180");
					$this->click("css=input[type=\"submit\"]");
					$this->waitForAjaxPageToLoad("30000");

					$this->assertTrue($this->isTextPresent("Record has been added"), "Could not duplicate node, error occured: ".$this->getText("css=.alert"));
					$this->click("xpath=(//img[@alt='Add sibling'])[5]");
					sleep(2);
					$this->type("name=duplicatedNodeForm[id_-*-*?1!-*?2!-*?2!-*?7!-*?1!]", "181");
					$this->select("name=duplicatedNodeForm[protocol_transport_-*-*?1!-*?2!-*?2!-*?7!-*?6!]", "label=UDP");
					$this->click("css=input[type=\"submit\"]");
					$this->waitForAjaxPageToLoad("30000");

					$this->assertTrue($this->isTextPresent("Record has been added"), "Could not duplicate node, error occured: ".$this->getText("css=.alert"));
					$this->click("xpath=(//img[@alt='Remove child'])[6]");
					sleep(2);
					$this->click("css=input[type=\"submit\"]");
					$this->waitForAjaxPageToLoad("30000");

					$this->assertTrue($this->isTextPresent("Failed to apply configuration to device."), "Node has been removed, even thought it shouldn't. This message appears: ".$this->getText("css=.alert"));

					$this->click("xpath=(//img[@alt='Remove child'])[5]");
					sleep(2);
					$this->click("css=input[type=\"submit\"]");
					$this->waitForAjaxPageToLoad("30000");

					$this->assertTrue($this->isTextPresent("Record has been removed."), "Could not remove node, error occured: ".$this->getText("css=.alert"));

					$this->select("name=configDataForm[protocol_transport_-*-*?1!-*?2!-*?1!-*?8!-*?6!]", "label=TCP");
					$this->click("css=input[type=\"submit\"]");
					$this->waitForAjaxPageToLoad("30000");

					$this->assertTrue($this->isTextPresent("Config has been edited successfully."), "Could not edit config correctly, error occured: ".$this->getText("css=.alert"));
					$this->assertSelectedValue("css=select[name=\"configDataForm[protocol_transport_-*-*?1!-*?2!-*?1!-*?8!-*?6!]\"]", "TCP", "Change to value TCP was not successfull, error occured: ".$this->getText("css=.alert"));
					$this->click("xpath=(//img[@alt='Remove child'])[4]");
					sleep(2);
					$this->click("css=input[type=\"submit\"]");
					$this->waitForAjaxPageToLoad("30000");

					$this->assertTrue($this->isTextPresent("Record has been removed."), "Could not remove node, error occured: ".$this->getText("css=.alert"));

				} else {
					$this->fail("Could not test Hanic probes/Exporters duplicate, edit and remove node.");
				}
			} else {
				$this->fail("Could not test Hanic probes duplicate node.");
			}
		}
	}

	private function handleLockAndUnlock() {
		$this->click("//nav[@id='block--topMenu']/a[2]/span");
		$this->waitForAjaxPageToLoad("30000");

		$this->assertTrue($this->isTextPresent("Successfully locked."), "Error while locking data-store, error occured: ".$this->getText("css=.alert"));

		$this->click("link=Connections");
		$this->waitForAjaxPageToLoad("30000");
		$this->click("css=#row-1 > td.configure > a");
		$this->waitForAjaxPageToLoad("30000");

		$this->click("css=input[type=\"submit\"]");
		$this->waitForAjaxPageToLoad("30000");

		$this->assertTrue($this->isTextPresent("Error: The request requires a resource that is already in use."), "Edit config on locked resource should be disallowed, error occured: ".$this->getText("css=.alert"));

		$this->click("//nav[@id='block--topMenu']/a[2]/span");
		$this->waitForAjaxPageToLoad("30000");

		$this->assertTrue($this->isTextPresent("Could not lock datastore"), "Locking device, which is already locked, should be disallowed, error occured: ".$this->getText("css=.alert"));

		$this->click("link=Connections");
		$this->waitForAjaxPageToLoad("30000");
		$this->click("link=Configure device");
		$this->waitForAjaxPageToLoad("30000");
		$this->click("//nav[@id='block--topMenu']/a[2]/span");
		$this->waitForAjaxPageToLoad("30000");

		$this->assertTrue($this->isTextPresent("Successfully unlocked."), "Error while unlocking data-store, error occured: ".$this->getText("css=.alert"));


		$this->click("link=Connections");
		$this->waitForAjaxPageToLoad("30000");
		$this->click("css=#row-1 > td.configure > a");
		$this->waitForAjaxPageToLoad("30000");
		$this->click("//nav[@id='block--topMenu']/a[2]/span");
		$this->waitForAjaxPageToLoad("30000");

		$this->assertTrue($this->isTextPresent("Successfully locked."), "Error while locking data-store, error occured: ".$this->getText("css=.alert"));
		$this->click("css=input[type=\"submit\"]");
		$this->waitForAjaxPageToLoad("30000");

		$this->assertTrue($this->isTextPresent("Config has been edited successfully."), "Device should be locked and edit-config should pass, error occured: ".$this->getText("css=.alert"));

		$this->click("//nav[@id='block--topMenu']/a[2]/span");
		$this->waitForAjaxPageToLoad("30000");
		$this->assertTrue($this->isTextPresent("Successfully unlocked."), "Error while unlocking data-store, error occured: ".$this->getText("css=.alert"));
	}
}
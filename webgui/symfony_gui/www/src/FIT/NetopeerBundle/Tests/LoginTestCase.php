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
 * Tests login into secured area of the app.
 */
class LoginTestCase extends DefaultTestCase
{
	/**
	 * test login to webGUI
	 *
	 * @throws Exception
	 */
	public function testLogin()
	{
		$this->open(self::$browserUrl);

		if ($this->isTextPresent("Log out")) {
			$this->click("link=Log out");
			$this->waitForPageToLoad("30000");
		}

		// check invalid username and password
		$this->type("id=username", "dfasfdahsofhdasdfiasjdfpasjdfpasijfpasjfdpasdf");
		$this->type("id=password", "dfadfadsfasf");
		$this->click("name=login");
		$this->waitForPageToLoad("30000");
		$this->assertFalse($this->isTextPresent("Bad credentials."), "Checking invalid username and password failed");

		// check valid username and invalid password
		$this->type("id=username", "dalexa");
		$this->type("id=password", "dfadfadsfasf");
		$this->click("name=login");
		$this->waitForPageToLoad("30000");
		$this->assertTrue($this->isTextPresent("The presented password is invalid."), "Checking valid username and invalid password failed");

		// if connected correctly
		if ($this->loginCorrectly()) {
			// try to log out
			$this->click("link=Log out");
			$this->waitForPageToLoad("30000");
			try {
				$this->assertTrue($this->isTextPresent("Log in is required for this site!"));
			} catch (PHPUnit_Framework_AssertionFailedError $e) {
				throw new \Exception('Could not log out.');
			}
		} else {
			throw new \Exception('Could not log in correctly.');
		}
	}
}
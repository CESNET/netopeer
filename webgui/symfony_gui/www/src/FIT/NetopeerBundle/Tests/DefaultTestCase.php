<?php
/**
 * Parent class for all Selenium test cases.
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
class DefaultTestCase extends PHPUnit_Extensions_SeleniumTestCase
{
	/**
	 * @var string  default URL for test
	 */
	protected static $browserUrl = "https://sauvignon.liberouter.org/symfony/app.php/";
	protected static $login = array(
		'host' => "sauvignon.liberouter.org",
		'user' => "seleniumTest",
		'pass' => "seleniumTestPass"
	);

	/**
	 * @inheritdoc
	 */
	protected function setUp()
	{
//		$this->setBrowser("*firefox");
		$this->setBrowser("*safari");
		$this->setBrowserUrl(self::$browserUrl);
	}

	/**
	 * overload default method call and add some more actions,
	 * for example resizing window to maximum available space
	 *
	 * @param string $url  url, which we want to open
	 * $return @inheritdoc
	 */
	protected function open($url) {
		$this->windowMaximize();
		parent::open($url);
		$this->windowMaximize();
		$this->checkPageError();
	}

	/**
	 * checking changing layout between single and double columns
	 */
	public function checkColumnsChange() {
		$this->click("link=Double column");
		$this->waitForAjaxPageToLoad("30000");
		$this->checkPageError();
		$this->assertTrue($this->isTextPresent("Config data only"), "Could not change to double-column layout.");

		$this->click("link=Single column");
		$this->waitForAjaxPageToLoad("30000");
		$this->checkPageError();
		$this->assertFalse($this->isTextPresent("Config data only"), "Could not change to single-column layout.");
	}

	/**
	 * connect to device with right credentials
	 *
	 * @throws Exception
	 */
	public function connectToDevice() {
		$this->checkPageError();

		// type connection credentials and try to connect to the device
		$this->type("id=form_host", self::$login['host']);
		$this->type("id=form_user", self::$login['user']);
		$this->type("id=form_password", self::$login['pass']);
		$this->click("css=input[type=\"submit\"]");
		$this->waitForAjaxPageToLoad("30000");
		try {
			$this->assertFalse($this->isTextPresent("Could not connect"));
		} catch (PHPUnit_Framework_AssertionFailedError $e) {
			throw new \Exception('Could not connect to server.');
		}
	}

	/**
	 * login to webgui with right credentials
	 *
	 * @return bool
	 */
	public function loginCorrectly() {
		try {
			$this->assertFalse($this->isTextPresent("Log in is required for this site!"));
			return true;
		} catch (PHPUnit_Framework_AssertionFailedError $e) {
		}

			$this->type("id=username", "seleniumTest");
			$this->type("id=password", "seleniumTestPass");
			$this->click("name=login");
			$this->waitForPageToLoad("30000");

		$this->checkPageError();

		try {
			$this->assertFalse($this->isTextPresent("Log in is required for this site!"));
			return true;
		} catch (PHPUnit_Framework_AssertionFailedError $e) {
			return false;
		}
	}

	/**
	 * Waits for ajax request is complete - ajax alternative for waitForPageToLoad
	 */
	public function waitForAjaxPageToLoad($time) {
		$this->waitForCondition("selenium.browserbot.getCurrentWindow().jQuery.active == 0", $time);
		sleep(5);
		$this->checkPageError();
	}

	/**
	 * checks, if all images are loaded correctly
	 *
	 * @throws Exception
	 */
	public function checkImages() {
		try {
			$this->assertEquals('1', $this->getEval('
				var elems = window.document.getElementsByTagName("img");
				var allOk = true;

				for(var i = 0; i < elems.length; i++) {
					var src = elems[i].src;
					if (src.indexOf("googleads") > 0) {
						continue;
					}
					allOk &= elems[i].complete && typeof elems[i].naturalWidth != "undefined" && elems[i].naturalWidth > 0;
				}
				Number(allOk); // getEval returns result of last statement. This statement has value of the variable as result.
			'));
		} catch (\Exception $e) {
			throw new \PHPUnit_Framework_AssertionFailedError('Some images were not loaded correctly.');
		}
	}

	/**
	 * checks appearance of Error document, Exception, Warning...
	 *
	 * @throws Exception when error, exception appears
	 */
	protected function checkPageError()	{
		try {
			$this->checkImages();
			$this->assertFalse($this->isElementPresent('css=.block_exception_detected'), 'Exception found, error 500.');
			$this->assertFalse($this->isTextPresent("404 Not Found"), "Error 404");
			$this->assertFalse($this->isTextPresent("Warning: "), "Warning appears.");
			$this->assertFalse($this->isTextPresent("Fatal error: "), "Fatal error appears.");
		} catch (PHPUnit_Framework_AssertionFailedError $e) {
			throw new \Exception('Error while loading page: ' . $this->getTitle() . ' with error ' . $e->toString());
		}
	}
}
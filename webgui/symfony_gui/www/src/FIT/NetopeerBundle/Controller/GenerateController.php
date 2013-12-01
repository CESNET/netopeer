<?php
/**
 * Controller for custom text output, for example XML or HTML file.
 *
 * @file GenerateController.php
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
 *
 */
namespace FIT\NetopeerBundle\Controller;

use FIT\NetopeerBundle\Controller\BaseController;

// these import the "@Route" and "@Template" annotations
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Generate simple output, for example model in XML or HTML (using templates)
 */
class GenerateController extends BaseController
{
	/**
	 * Gets XML subtree from model (according to given xPath) and shows it either as rendered HTML or as clean XML
	 *
	 * @Route("/generate/{level}/{xPath}/{key}/{module}/{subsection}/model.{_format}", defaults={"module" = null, "subsection" = null, "_format" = "html"}, requirements={"_format" = "html|xml"}, name="generateFromModel")
	 * @Template()
	 *
	 * @param $level
	 * @param $xPath
	 * @param int $key                    section key
	 * @param string|null $module         module identifier (url)
	 * @param string|null $subsection     subsection identifier (url)
	 * @param string      $_format        output format
	 * @return array
	 */
	public function generateXMLFromModelAction($level, $xPath, $key, $module = null, $subsection = null, $_format = 'html') {
		// DependencyInjection (DI) - defined in Resources/config/services.yml
		$dataClass = $this->get('DataModel');

		// get XML tree from model
		$xml = $dataClass->getXMLFromModel(urldecode($xPath), $key, $module, $subsection);

		// if we want to get html, we will build tree for HTML form
		if ( $_format == 'html' ) {
			$simpleXml = simplexml_load_string($xml, 'SimpleXMLIterator');
			$this->assign('level', $level);
			$this->assign('xmlArr', $simpleXml);	
		// or we just want to see XML (for example, for adding new values in Data.php or load as SimpleXML)
		} else {
			echo $xml;
			exit;
		}

		return $this->getTwigArr();
	}
}

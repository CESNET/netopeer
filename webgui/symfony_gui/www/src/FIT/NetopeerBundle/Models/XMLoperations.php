<?php
/**
 * XML operations, which are necessary for processing XML modifications.
 *
 * @file XMLoperations.php
 * @author David Alexa <alexa.david@me.com>
 * @author Tomas Cejka <cejkat@cesnet.cz>
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
namespace FIT\NetopeerBundle\Models;

use Symfony\Component\DependencyInjection\ContainerInterface;
use FIT\NetopeerBundle\Models\Data as Data;
use Symfony\Component\Finder\Finder;

class XMLoperations {
	/**
	 * @var ContainerInterface   base bundle container
	 */
	public $container;
	/**
	 * @var \Symfony\Bridge\Monolog\Logger       instance of logging class
	 */
	public $logger;
	/**
	 * @var \FIT\NetopeerBundle\Models\Data       instance of data class
	 */
	public $dataModel;

	/**
	 * Constructor with DependencyInjection params.
	 *
	 * @param \Symfony\Component\DependencyInjection\ContainerInterface $container
	 * @param \Symfony\Bridge\Monolog\Logger $logger   logging class
	 * @param Data $dataModel data class
	 */
	public function __construct(ContainerInterface $container, $logger, Data $dataModel)	{
		$this->container = $container;
		$this->logger = $logger;
		$this->dataModel = $dataModel;
	}



	/**
	 * divides string into the array (name, value) (according to the XML tree node => value)
	 *
	 * @param  string $postKey post value
	 * @return array           modified array
	 */
	public function divideInputName($postKey)
	{
		$values = explode('_', $postKey);
		$cnt = count($values);
		if ($cnt > 2) {
			$last = $values[$cnt-1];
			$values = array(implode("_", array_slice($values, 0, $cnt-1)), $last);
		}
		return $values;
	}

	/**
	 * decodes XPath value
	 *
	 * @param  string $value encoded XPath string
	 * @return string        decoded XPath string
	 */
	public function decodeXPath($value) {
		return str_replace(
			array('--', '?', '!'),
			array('/', '[', ']'),
			$value
		);
	}

	/**
	 * Completes request tree (XML) with necessary nodes (parent nodes).
	 * Tree must be valid for edit-config action
	 *
	 * @param \SimpleXMLElement  $tmpConfigXml
	 * @param string            $config_string
	 * @return \SimpleXMLElement
	 */
	public function completeRequestTree(&$tmpConfigXml, $config_string) {

		$subroot = simplexml_load_file($this->dataModel->getPathToModels() . 'wrapped.wyin');
		$xmlNameSpaces = $subroot->getNamespaces();

		if ( isset($xmlNameSpaces[""]) ) {
			$subroot->registerXPathNamespace("xmlns", $xmlNameSpaces[""]);
		}
		$ns = $subroot->xpath("//xmlns:namespace");
		$namespace = "";
		if (sizeof($ns)>0) {
			$namespace = $ns[0]->attributes()->uri;
		}

		$parent = $tmpConfigXml->xpath("parent::*");
		while ($parent) {
			$pos_subroot[] = $parent[0];
			$parent = $parent[0]->xpath("parent::*");
		}
		$config = $config_string;
		for ($i = 0; $i < sizeof($pos_subroot); $i++) {
			$tmp = $pos_subroot[$i]->getName();
			$config .= "</".$pos_subroot[$i]->getName().">\n";

			if ($i == sizeof($pos_subroot) - 1) {
				$config = "<".$pos_subroot[$i]->getName().
						($namespace!==""?" xmlns=\"$namespace\"":"").
						" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\"".
						">\n".$config;
			} else {
				$config = "<".$pos_subroot[$i]->getName().
						">\n".$config;
			}
		}
		$result = simplexml_load_string($config);
		$result->registerXPathNamespace('xmlns', $namespace);

		return $result;
	}

	/**
	 * updates (modifies) value of XML node
	 *
	 * @param  string $configXml   xml file
	 * @param  string $elementName name of the element
	 * @param  string $xpath       XPath to the element
	 * @param  string $val         new value
	 * @param  string $xPathPrefix
	 * @return \SimpleXMLElement   modified node
	 */
	public function elementValReplace(&$configXml, $elementName, $xpath, $val, $xPathPrefix = "xmlns:")
	{
		$isAttribute = false;

		// if element is an attribute, it will have prefix at-
		if ( strrpos($elementName, 'at-') === 0 ) {
			$elementName = substr($elementName, 3);
			$isAttribute = true;
		}

		// get node according to xPath query
		$node = $configXml->xpath('/'.$xPathPrefix.$xpath);

		if (isset($node[0])) {
			$node = $node[0];
		}

		// set new value for node
		if ( $isAttribute === true ) {
			$elem = $node[0];
			$elem[$elementName] = $val;
		} else {
			if (isset($node[0])) {
				$elem = $node[0];
			} else {
				$elem = $node;
			}

			if (isset($elem->$elementName) && (sizeof($elem->$elementName) > 0)) {
				$e = $elem->$elementName;
				$e[0] = str_replace("\r", '', $val); // removes \r from value
			} else {
				if ( !is_array($elem) ) {
					$elem[0] = str_replace("\r", '', $val);
				}
			}
		}

		return $elem;
	}


	/**
	 * handles edit config form - changes config values into the $_POST values
	 * and sends them to editConfig process
	 *
	 * @param  int $key  session key of current connection
	 * @param  array $configParams    array of config params
	 * @return int        result code
	 */
	public function handleEditConfigForm(&$key, $configParams) {
		$post_vals = $this->container->get('request')->get('configDataForm');
		$res = 0;

		try {

			if ( ($configXml = $this->dataModel->handle('getconfig', $configParams, false)) != 1 ) {
				$configXml = simplexml_load_string($configXml, 'SimpleXMLIterator');

				// save to temp file - for debugging
				if ($this->container->getParameter('kernel.environment') == 'dev') {
					file_put_contents($this->container->get('kernel')->getRootDir().'/logs/tmp-files/original.yin', $configXml->asXml());
				}

				// we will get namespaces from original getconfig and set them to simpleXml object, 'cause we need it for XPath queries
				$xmlNameSpaces = $configXml->getNamespaces();

				if ( isset($xmlNameSpaces[""]) ) {
					$configXml->registerXPathNamespace("xmlns", $xmlNameSpaces[""]);
					$xPathPrefix = "xmlns:";
				} else {
					// we will use this xmlns as backup for XPath request
					$configXml->registerXPathNamespace("xmlns", "urn:cesnet:tmc:hanicprobe:1.0");
					$xPathPrefix = "";
				}

				// foreach over all post values
				foreach ( $post_vals as $postKey => $val ) {
					$values = $this->divideInputName($postKey);
					$elementName = $values[0];
					$xpath = $this->decodeXPath($values[1]);
					$xpath = substr($xpath, 1); // removes slash at the begining

					$this->elementValReplace($configXml, $elementName, $xpath, $val, $xPathPrefix);
				}

				// for debugging, edited configXml will be saved into temp file
				if ($this->container->getParameter('kernel.environment') == 'dev') {
					file_put_contents($this->container->get('kernel')->getRootDir().'/logs/tmp-files/edited.yin', $configXml->asXml());
				}

				$res = $this->executeEditConfig($key, $configXml->asXml(), $configParams['source']);
				if ($res !== 1) {
					$this->container->get('session')->getFlashBag()->add('success', "Config has been edited successfully.");
				}
			} else {
				throw new \ErrorException("Could not load config.");
			}

		} catch (\ErrorException $e) {
			$this->logger->warn('Could not save config correctly.', array('error' => $e->getMessage()));
			$this->container->get('request')->getSession()->getFlashBag()->add('error', "Could not save config correctly. Error: ".$e->getMessage());
		}

		return $res;
	}

	/**
	 * duplicates node in config - values of duplicated nodes (elements)
	 *
	 * could be changed by user
	 *
	 * @param  int  $key  session key of current connection
	 * @param  array $configParams    array of config params
	 * @throws \ErrorException
	 * @return int        result code
	 */
	public function handleDuplicateNodeForm(&$key, $configParams)	{
		$post_vals = $this->container->get('request')->get('duplicatedNodeForm');
		$res = 0;

		try {
			// load original (not modified) getconfig
			if ( ($originalXml = $this->dataModel->handle('getconfig', $configParams, false)) != 1 ) {
				$tmpConfigXml = simplexml_load_string($originalXml);

				// save to temp file - for debugging
				if ($this->container->getParameter('kernel.environment') == 'dev') {
					file_put_contents($this->container->get('kernel')->getRootDir().'/logs/tmp-files/original.yin', $tmpConfigXml->asXml());
				}

				// we will get namespaces from original getconfig and set them to simpleXml object, 'cause we need it for XPath queries
				$xmlNameSpaces = $tmpConfigXml->getNamespaces();
				if ( isset($xmlNameSpaces[""]) ) {
					$tmpConfigXml->registerXPathNamespace("xmlns", $xmlNameSpaces[""]);
				}
			}

			// if we have XML configuration
			if (isset($tmpConfigXml)) {

				// we will go through all posted values
				$newLeafs = array();

//				$tmpConfigXml = $this->completeRequestTree($tmpConfigXml, $tmpConfigXml->asXml());

				/* fill values */
				$i = 0;
				$createString = "";

				foreach ( $post_vals as $postKey => $val ) {
					$values = $this->divideInputName($postKey);
					// values[0] - label
					// values[1] - encoded xPath

					if ($postKey == "parent") {
						$xpath = $this->decodeXPath($val);
						// get node according to xPath query
						$parentNode = $tmpConfigXml->xpath($xpath);
					} else if ( count($values) != 2 ) {
						$this->logger->err('newNodeForm must contain exactly 2 params, example container_-*-*?1!-*?2!-*?1!', array('values' => $values, 'postKey' => $postKey));
						throw new \ErrorException("newNodeForm must contain exactly 2 params, example container_-*-*?1!-*?2!-*?1! ". var_export(array('values' => $values, 'postKey' => $postKey), true));
					} else {
						$xpath = $this->decodeXPath($values[1]);
						$xpath = substr($xpath, 1, strripos($xpath, "/") - 1);

						$node = $this->elementValReplace($tmpConfigXml, $values[0], $xpath, $val);
						try {
							if ( is_object($node) ) {
								$node->addAttribute("xc:operation", "create", "urn:ietf:params:xml:ns:netconf:base:1.0");
							}
						} catch (\ErrorException $e) {
							// nothing happened - attribute is already there
						}
					}
				}

				$createString = "\n".str_replace('<?xml version="1.0"?'.'>', '', $parentNode[0]->asXml());
				$createTree = $this->completeRequestTree($parentNode[0], $createString);

				// for debugging, edited configXml will be saved into temp file
				if ($this->container->getParameter('kernel.environment') == 'dev') {
					file_put_contents($this->container->get('kernel')->getRootDir().'/logs/tmp-files/newElem.yin', $createTree->asXml());
				}
				$res = $this->executeEditConfig($key, $createTree->asXml(), $configParams['source']);

				if ($res == 0) {
					$this->container->get('request')->getSession()->getFlashBag()->add('success', "Record has been added.");
				}
			} else {
				throw new \ErrorException("Could not load config.");
			}

		} catch (\ErrorException $e) {
			$this->logger->warn('Could not save new node correctly.', array('error' => $e->getMessage()));
			$this->container->get('request')->getSession()->getFlashBag()->add('error', "Could not save new node correctly. Error: ".$e->getMessage());
		}

		return $res;
	}

	/**
	 * create new node in config - according to the values in XML model
	 *
	 * could be changed by user
	 *
	 * @param  int      $key 				  session key of current connection
	 * @param  string   $module 		  module name
	 * @param  string   $subsection  	subsection name
	 * @return int                    result code
	 */
	public function handleGenerateNodeForm(&$key, &$module, &$subsection)	{
		$post_vals = $this->container->get('request')->get('generatedNodeForm');
		$res = 0;

		// TODO: load XML file - https://sauvignon.liberouter.org/symfony/generate/2/-%252A-%252A%253F1%2521-%252A%253F2%2521-%252A%253F1%2521/0/hanic-probe/exporters/model.xml
		// this URL should be generated from route (path = generateFromModel, params: '2' = level (whatever, not used in this case); 'xPath' = url_encode($xPath), 'key' = $key, 'module' = $module, 'subsection' = subsection, '_format' = 'xml')
		//
		// change values to $_POST ones if XML file has been loaded correctly
		// generate (completeTree) output XML for edit-config

		return $res;
	}

	/**
	 * create new node
	 *
	 * @param  int      $key 				  session key of current connection
	 * @param  array $configParams    array of config params
	 * @return int                    result code
	 */
	public function handleNewNodeForm(&$key, $configParams)	{
		$post_vals = $this->container->get('request')->get('newNodeForm');
		$res = 0;

		try {
			// load original (not modified) getconfig
			if ( ($originalXml = $this->dataModel->handle('getconfig', $configParams, true)) != 1 ) {
				/** @var \SimpleXMLElement $tmpConfigXml */
				$tmpConfigXml = simplexml_load_string($originalXml);

				// we will get namespaces from original getconfig and set them to simpleXml object, 'cause we need it for XPath queries
				$xmlNameSpaces = $tmpConfigXml->getNamespaces();
				if ( isset($xmlNameSpaces[""]) ) {
					$tmpConfigXml->registerXPathNamespace("xmlns", $xmlNameSpaces[""]);
				}
			}

			// if we have XML configuration
			$skipArray = array();
			if (isset($tmpConfigXml)) {

				// load parent value
				if (array_key_exists('parent', $post_vals)) {
					$parentPath = $post_vals['parent'];

					$xpath = $this->decodeXPath($parentPath);
					// get node according to xPath query
					/** @var \SimpleXMLElement $parentNode */
					$parentNode = $tmpConfigXml->xpath($xpath);

					array_push($skipArray, 'parent');

					// we have to delete all children from parent node (because of xpath selector for new nodes), except from key nodes
					$domNode = dom_import_simplexml($parentNode[0]);
					$this->removeChildrenExceptKey($domNode, $domNode->childNodes);

				} else {
					throw new \ErrorException("Could not set parent node for new elements.");
				}

				// we will go through all post values
				foreach ( $post_vals as $labelKey => $labelVal ) {
					if (in_array($labelKey, $skipArray)) continue;
					$label = $this->divideInputName($labelKey);
					// values[0] - label
					// values[1] - encoded xPath

					// load parent node


					if ( count($label) != 2 ) {
						$this->logger->err('newNodeForm must contain exactly 2 params, example container_-*-*?1!-*?2!-*?1!', array('values' => $label, 'postKey' => $labelKey));
						throw new \ErrorException("Could not proccess all form fields.");

					} else {
						$valueKey = str_replace('label', 'value', $labelKey);
						$value = $post_vals[$valueKey];

						array_push($skipArray, $labelKey);
						array_push($skipArray, $valueKey);

						$xpath = $this->decodeXPath($label[1]);
						$xpath = substr($xpath, 1, strripos($xpath, "/") - 1);

						$node = $this->insertNewElemIntoXMLTree($tmpConfigXml, $xpath, $labelVal, $value);

					}
				}

				$createString = "\n".str_replace('<?xml version="1.0"?'.'>', '', $parentNode[0]->asXml());
				$createTree = $this->completeRequestTree($parentNode[0], $createString);

				$res = $this->executeEditConfig($key, $createTree->asXml(), $configParams['source']);

				if ($res == 0) {
					$this->container->get('request')->getSession()->getFlashBag()->add('success', "Record has been added.");
				}
			} else {
				throw new \ErrorException("Could not load config.");
			}

		} catch (\ErrorException $e) {
			$this->logger->warn('Could not save new node correctly.', array('error' => $e->getMessage()));
			$this->container->get('request')->getSession()->getFlashBag()->add('error', "Could not save new node correctly. Error: ".$e->getMessage());
		}

		return $res;
	}

	/**
	 * @param $domNode
	 * @param $domNodeChildren
	 */
	public function removeChildrenExceptKey($domNode, $domNodeChildren)
	{
		$keyElems = 0;
		while ($domNodeChildren->length > $keyElems) {
			if (count($domNodeChildren->item($keyElems)->childNodes)) {
				// $this->removeChildrenExceptKey($domNode, $domNodeChildren->item($keyElems)->childNodes); // TODO: make it recursive
			}
			$isKey = false;
			if ($domNodeChildren->item($keyElems)->hasAttributes()) {
				foreach ($domNodeChildren->item($keyElems)->attributes as $attr) {
					if ($attr->nodeName == "iskey" && $attr->nodeValue == "true") {
						if ($domNodeChildren->item($keyElems)->hasAttributes()) {
							foreach ($domNodeChildren->item($keyElems)->attributes as $attr) {
								$attributesArr[] = $attr->nodeName;
							}
							// remove must be in new foreach, previous deletes only first one
							foreach ($attributesArr as $attrName) {
								$domNodeChildren->item($keyElems)->removeAttribute($attrName);
							}
						}
						$keyElems++;
						$isKey = true;
						break;
					}
				}
			}
			if (!$isKey) {
				try {
					$domNode->removeChild($domNodeChildren->item($keyElems));
				} catch (\DOMException $e) {

				}
			}
		}

		if ($domNode->hasAttributes()) {
			foreach ($domNode->attributes as $attr) {
				$attributesArr[] = $attr->nodeName;
			}
			// remove must be in new foreach, previous deletes only first one
			foreach ($attributesArr as $attrName) {
				$domNode->removeAttribute($attrName);
			}
		}
		return;
	}

	/**
	 * inserts new element into given XML tree
	 *
	 * @param  \SimpleXMLElement $configXml   xml file
	 * @param  string $xpath       XPath to the element
	 * @param  string $label       label value
	 * @param  string $value       new value
	 * @param  string $xPathPrefix
	 *
	 * @return \SimpleXMLElement   modified node
	 */
	public function insertNewElemIntoXMLTree(&$configXml, $xpath, $label, $value, $xPathPrefix = "xmlns:")
	{
		/**
		 * get node according to xPath query
		 * @var \SimpleXMLElement $node
		 */
		$node = $configXml->xpath('/'.$xPathPrefix.$xpath);
		if (!$value || $value === "") {
			$elem = $node[0]->addChild($label);
		} else {
			$elem = $node[0]->addChild($label, $value);
		}
		$elem->addAttribute("xc:operation", "create", "urn:ietf:params:xml:ns:netconf:base:1.0");

		return $elem;
	}

	/**
	 * removes node from config XML tree
	 *
	 * @param  int  $key session key of current connection
	 * @param  array $configParams    array of config params
	 * @throws \ErrorException  when get-config could not be loaded
	 * @return int       result code
	 */
	public function handleRemoveNodeForm(&$key, $configParams) {
		$post_vals = $this->container->get('request')->get('removeNodeForm');
		$res = 0;

		try {
			if ( ($originalXml = $this->dataModel->handle('getconfig', $configParams, false)) != 1 ) {
				$tmpConfigXml = simplexml_load_string($originalXml);

				// save to temp file - for debugging
				if ($this->container->getParameter('kernel.environment') == 'dev') {
					file_put_contents($this->container->get('kernel')->getRootDir().'/logs/tmp-files/original.yin', $tmpConfigXml->asXml());
				}

				// we will get namespaces from original getconfig and set them to simpleXml object, 'cause we need it for XPath queries
				$xmlNameSpaces = $tmpConfigXml->getNamespaces();
				if ( isset($xmlNameSpaces[""]) ) {
					$tmpConfigXml->registerXPathNamespace("xmlns", $xmlNameSpaces[""]);
				}

				$xpath = $this->decodeXPath($post_vals["parent"]);
				$toDelete = $tmpConfigXml->xpath($xpath);
				$deletestring = "";

				foreach ($toDelete as $td) {
					//$td->registerXPathNamespace("xc", "urn:ietf:params:xml:ns:netconf:base:1.0");
					$td->addAttribute("xc:operation", "remove", "urn:ietf:params:xml:ns:netconf:base:1.0");
					$deletestring .= "\n".str_replace('<?xml version="1.0"?'.'>', '', $td->asXml());
				}

				$deleteTree = $this->completeRequestTree($toDelete[0], $deletestring);

				// for debugging, edited configXml will be saved into temp file
				if ($this->container->getParameter('kernel.environment') == 'dev') {
					file_put_contents($this->container->get('kernel')->getRootDir().'/logs/tmp-files/removeNode.yin', $tmpConfigXml->asXml());
				}
				$res = $this->executeEditConfig($key, $tmpConfigXml->asXml(), $configParams['source']);
				if ($res == 0) {
					$this->container->get('request')->getSession()->getFlashBag()->add('success', "Record has been removed.");
				}
			} else {
				throw new \ErrorException("Could not load config.");
			}
		} catch (\ErrorException $e) {
			$this->logger->warn('Could not remove node correctly.', array('error' => $e->getMessage()));
			$this->container->get('request')->getSession()->getFlashBag()->add('error', "Could not remove node correctly. ".$e->getMessage());
		}

		return $res;

	}

	/**
	 * sends modified XML to server
	 *
	 * @param  int    $key    	session key of current connection
	 * @param  string $config 	XML document which will be send
	 * @param  string $target = "running" target source
	 * @return int						  return 0 on success, 1 on error
	 */
	private function executeEditConfig($key, $config, $target = "running") {
		$res = 0;
		$editConfigParams = array(
			'key' 	 => $key,
			'target' => $target,
			'config' => str_replace('<?xml version="1.0"?'.'>', '', $config)
		);

		// edit-cofig
		if ( ($merged = $this->dataModel->handle('editconfig', $editConfigParams)) != 1 ) {
			// for debugging purposes, we will save result into the temp file
			if ($this->container->getParameter('kernel.environment') == 'dev') {
				file_put_contents($this->container->get('kernel')->getRootDir().'/logs/tmp-files/merged.yin', $merged);
			}
		} else {
			$this->logger->err('Edit-config failed.', array('params', $editConfigParams));
			// throw new \ErrorException('Edit-config failed.');
			$res = 1;
		}
		return $res;
	}

	/**
	 * Removes <?xml?> header from text.
	 *
	 * @param   string &$text  string to remove XML header in
	 * @return  mixed         returns an array if the subject parameter
	 *                        is an array, or a string otherwise.	If matches
	 *                        are found, the new subject will be returned,
	 *                        otherwise subject will be returned unchanged
	 *                        or null if an error occurred.
	 */
	public function removeXmlHeader(&$text) {
		return preg_replace("/<\?xml .*\?".">/i", "n", $text);
	}


	/**
	 * Merge given XML with data model
	 *
	 * @param $xml
	 * @return int|array 1 on error, merged array on success
	 */
	public function mergeXMLWithModel(&$xml) {
		// load model
		$notEditedPath = $this->dataModel->getModelsDir();
		$path = $this->dataModel->getPathToModels();
		$modelFile = $path . 'wrapped.wyin';

		$this->logger->info("Trying to find model in ", array('pathToFile' => $modelFile));

		if ( file_exists($modelFile) ) {
			$this->logger->info("Model found in ", array('pathToFile' => $modelFile));
			if ( $path != $notEditedPath ) {
				$model = simplexml_load_file($modelFile);
				try {
					$res = $this->mergeWithModel($model, $xml);
				} catch (\ErrorException $e) {
					// TODO
					$this->logger->err("Could not merge with model");
					$res = 1;
				}
			} else {
				// TODO: if is not set module direcotory, we have to set model to merge with
				// problem: we have to load all models (for example combo, comet-tester...)
				$this->logger->warn("Could not find model in ", array('pathToFile' => $modelFile));
				$res = 1;
			}
		} else {
			$this->logger->warn("Could not find model in ", array('pathToFile' => $modelFile));
			$res = 1;
		}
		return $res;
	}

	/**
	 * Check, if XML response is valid.
	 *
	 * @param string            &$xmlString       xml response
	 * @return int  1 on success, 0 on error
	 */
	public function isResponseValidXML(&$xmlString) {
		$e = false;
		try {
			$simpleXMLRes = simplexml_load_string($xmlString);
		} catch (\ErrorException $e) {
			// Exception will be handled bellow
		}
		if ( (isset($simpleXMLRes) && $simpleXMLRes === false) || $e !== false) {
			// sometimes is exactly one root node missing
			// we will check, if is not XML valid with root node
			$xmlString = "<root>".$xmlString."</root>";
			try {
				$simpleXMLRes = simplexml_load_string($xmlString);
			} catch (\ErrorException $e) {
				return 0;
			}
		}
		return 1;
	}

	/**
	 * Get parent for element.
	 *
	 * @param $element
	 * @return bool|\SimpleXMLElement
	 */
	public function getElementParent($element) {
		$parents = $element->xpath("parent::*");
		if ($parents) {
			return $parents[0];
		}
		return false;
	}

	/**
	 * Check if two elements match.
	 *
	 * @param $model_el
	 * @param $possible_el
	 * @return bool
	 */
	public function checkElemMatch($model_el, $possible_el) {
		$mel = $this->getElementParent($model_el);
		$pel = $this->getElementParent($possible_el);

		if ($mel instanceof \SimpleXMLElement && $pel instanceof \SimpleXMLElement) {
			while ($pel && $mel) {
				if ($pel->getName() !== $mel->getName()) {
					return false;
				}
				$pel = $this->getElementParent($pel);
				$mel = $this->getElementParent($mel);
			}
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Completes tree structure for target element.
	 *
	 * @param \SimpleXMLElement $source
	 * @param \SimpleXMLElement $target
	 */
	public function completeAttributes(&$source, &$target) {
		if ($source->attributes()) {
			$attrs = $source->attributes();
			if (in_array($attrs["eltype"], array("leaf","list","leaf-list", "container"))) {
				foreach ($source->attributes() as $key => $val) {
					$target->addAttribute($key, $val);
				}
			}
		}
	}

	/**
	 * Find corresponding $el in configuration model $model and complete attributes from $model.
	 *
	 * @param  \SimpleXMLElement &$model with data model
	 * @param  \SimpleXMLElement $el     with element of response
	 */
	public function findAndComplete(&$model, $el) {
		$modelns = $model->getNamespaces();
		$model->registerXPathNamespace("c", $modelns[""]);
		$found = $model->xpath("//c:". $el->getName());
		if (sizeof($found) == 1) {
			$this->completeAttributes($found[0], $el);
		} else {
			//echo "Not found unique<br>";
			foreach ($found as $found_el) {
				if ($this->checkElemMatch($el, $found_el)) {
					$this->completeAttributes($found_el, $el);
					break;
				}
			}
		}
	}

	/**
	 * Go through $root_el tree that represents the response from Netconf server.
	 *
	 * @param  \SimpleXMLElement &$model  with data model
	 * @param  \SimpleXMLElement $root_el with element of response
	 */
	public function mergeRecursive(&$model, $root_el) {
		foreach ($root_el as $ch) {
			$this->findAndComplete($model, $ch);
			$this->mergeRecursive($model, $ch);
		}

		foreach ($root_el->children as $ch) {
			$this->findAndComplete($model, $ch);
			$this->mergeRecursive($model, $ch);
		}
	}

	/**
	 * Add attributes from configuration model to response such as config, mandatory, type.
	 *
	 * @param  \SimpleXMLElement  $model 	data configuration model
	 * @param  string             $result data from netconf server
	 * @return string								      the result of merge
	 */
	public function mergeWithModel($model, $result) {
		if ($result) {
			$resxml = simplexml_load_string($result);

			$this->mergeRecursive($model, $resxml);

			return $resxml->asXML();
		} else {
			return $result;
		}
	}

	/**
	 * Validates input string against validation files saved in models directory.
	 * For now, only two validation step are set up - RelaxNG (*.rng) and Schema (*.xsd)
	 *
	 * @param string $xml   xml string to validate with RelaxNG and Schema, if available
	 * @return int          0 on success, 1 on error
	 */
	public function validateXml($xml) {
		$finder = new Finder();
		$domDoc = new \DOMDocument();
		$xml = "<mynetconfbase:data  xmlns:mynetconfbase='urn:ietf:params:xml:ns:netconf:base:1.0'>".$xml."</mynetconfbase:data>";
		$domDoc->loadXML($xml);

		$iterator = $finder
				->files()
				->name("/.*data\.(rng|xsd)$/")
				->in($this->dataModel->getPathToModels());

		try {
			foreach ($iterator as $file) {
				$path = $file->getRealPath();
				if (strpos($path, "rng")) {
					$domDoc->relaxNGValidate($path);
				} else if (strpos($path, "xsd")) {
					$domDoc->schemaValidate($path);
				}
			}
		} catch (\ErrorException $e) {
			$this->logger->warn("XML is not valid.", array('error' => $e->getMessage(), 'xml' => $xml, 'RNGfile' => $path));
			return 1;
		}

		return 0;

	}

	public function getAvailableLabelValuesForXPath($connectedDeviceId, $formId, $xPath, $configParams) {

		/**
		 * @var \winzou\CacheBundle\Cache\LifetimeFileCache $cache
		 */
		$cache = $this->container->get('winzou_cache');

		if ($cache->contains('getResponseForFormId_'.$formId)) {
			$xml = $cache->fetch('getResponseForFormId_'.$formId);
		} else {
			$xml = $this->dataModel->handle('getconfig', $configParams);
			$cache->save('getResponseForFormId_'.$formId, $xml, 1000);
		}

		$labelsArr = array();
		$attributesArr = array();
		$elemsArr= array();
		if ($xml != 1) {
			$dom = new \DOMDocument();
			$dom->loadXML($xml);

			$decodedXPath = str_replace("/", "/xmlns:", $this->decodeXPath($xPath))."/*";
			$domXpath = new \DOMXPath($dom);

			$context = $dom->documentElement;
			foreach( $domXpath->query('namespace::*', $context) as $node ) {
				$domXpath->registerNamespace($node->nodeName, $node->nodeValue);
			}

			$elements = $domXpath->query($decodedXPath);

			if (!is_null($elements)) {
				foreach ($elements as $element) {
					array_push($labelsArr, $element->nodeName);
					$elemsArr[$element->nodeName] = simplexml_import_dom($element, 'SimpleXMLIterator');
					if ($element->hasAttributes()) {
						foreach ($element->attributes as $attr) {
							$attributesArr[$element->nodeName][$attr->nodeName] = $attr->nodeValue;
						}
					}
				}
			}
		}
		$labelsArr = array_values(array_unique($labelsArr));

		$retArr['labels'] = $labelsArr;
		$retArr['labelsAttributes'] = $attributesArr;
		$retArr['elems'] = $elemsArr;
		return $retArr;
	}
}
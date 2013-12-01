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
namespace FIT\NetopeerBundle\Command;

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use FIT\NetopeerBundle\Entity\User;

/**
 * Handles creating, removing or editing users in DB
 *
 * Class UserCommand
 * @package FIT\NetopeerBundle\Command
 */
class UserCommand extends ContainerAwareCommand
{
	protected function configure() {
		$this->setName("app:user")
			->setHelp("Handles creating, removing or editing users in DB")
			->setDescription("Handles creating, removing or editing users in DB")
			->addOption(
				'action',
				null,
				InputOption::VALUE_OPTIONAL,
				'Set action add|edit|rm',
				'add'
			)
			->addOption(
					'user',
					null,
					InputOption::VALUE_REQUIRED,
					'Set user username'
			)
			->addOption(
				'pass',
				null,
				InputOption::VALUE_REQUIRED,
				'Set user password'
			)
			->addOption(
				'new-username',
				null,
				InputOption::VALUE_REQUIRED,
				'Set user new username'
			);
	}

	/**
	 * Executes adding, removing or editing user in DB
	 *
	 * @param InputInterface $intput
	 * @param OutputInterface $output
	 * @return int|null|void
	 */
	protected function execute(InputInterface $input, OutputInterface $output) {
		$command = $input->getOption("action");

		if (!$command) {
			$command = "add";
		}

		$username = $input->getOption('user');
		$password = $input->getOption('pass');
		$newusername = $input->getOption('new-username');

		if (!$username) {
			$output->writeln('Set --name!');
			return;
		}

		$em = $this->getContainer()->get('doctrine')->getEntityManager();

		if ($command == "add") {
			if ($password) {
				$user = new User();
				$user->setRoles("ROLE_ADMIN");
				$user->setUsername($username);

				$encoder = $this->getContainer()->get('security.encoder_factory')->getEncoder($user);
				$pass = $encoder->encodePassword($password, $user->getSalt());
				$user->setPassword($pass);

				try {
					$em->persist($user);
					$em->flush();
				} catch (\PDOException $e) {
					$output->writeln('User with username "'.$username.'" already exists.');
				}
			} else {
				$output->writeln('Please, set user password: --pass=password');
			}
		} elseif ($command == "edit") {
			$user = $em->getRepository('FITNetopeerBundle:User')->findOneBy(array(
				"username" => $username,
			));

			if (!$user) {
				$output->writeln('Selected user does not exists!');
				return;
			}

			if ($newusername) {
				$user->setUsername($newusername);
			}
			if ($password) {
				$encoder = $this->getContainer()->get('security.encoder_factory')->getEncoder($user);
				$pass = $encoder->encodePassword($password, $user->getSalt());
				$user->setPassword($pass);
			}
			try {
				$em->persist($user);
				$em->flush();
			} catch (\PDOException $e) {
				$output->writeln('Could not edit user  with username "'.$username.'".');
			}
		} elseif ($command == "rm") {
			/** @var $dialog DialogHelper */
			$dialog = $this->getHelperSet()->get('dialog');

			while ( true ) {
				$command = $dialog->ask($output, 'Do you realy want to delete user "'.$username.'"? [y/n]: ');
				try {
					if ( $command ) {
						if ($command == "y") {
							$user = $em->getRepository('FITNetopeerBundle:User')->findOneBy(array(
								"username" => $username,
							));

							if (!$user) {
								$output->writeln('Selected user does not exists!');
								return;
							}

							try {
								$em->remove($user);
								$em->flush();
							} catch (\PDOException $e) {
								$output->writeln('Could not remove user  with username "'.$username.'".');
							}
						}
						return;
					}
				} catch (\Exception $e) {
					$output->writeln('<error>'.$e.'</error>');
				}
			}
			exit;
		}
	}
}
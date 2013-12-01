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
use Symfony\Component\Process\Process;

use FIT\NetopeerBundle\Entity\User;

/**
 * Handles actions after composer install,update
 *
 * Class UserCommand.php
 * @package FIT\NetopeerBundle\Command
 */
class ProjectInitCommand extends ContainerAwareCommand
{
	protected function configure() {
		$this->setName("app:install")
			->setHelp("Handles actions after composer install,update")
			->setDescription("Handles actions after composer install,update")
			->addOption(
				'post',
				null,
				InputOption::VALUE_REQUIRED,
				'Set post action install|update'
			);
	}

	/**
	 * Executes post install SH script
	 *
	 * @param InputInterface $intput
	 * @param OutputInterface $output
	 */
	protected function execute(InputInterface $input, OutputInterface $output) {
		$command = $input->getOption("post");

		$output->writeln("");
		$output->writeln("========================");
		$output->writeln('Executing post '. $command. ' script.');
		$output->writeln("========================");

		$process = new Process("/bin/bash ./src/FIT/NetopeerBundle/bin/netconfwebgui-postinstall.sh");
		$process->run();

		while ($process->isRunning()) {
			$process->getIncrementalOutput();
			$process->getIncrementalErrorOutput();
		}

		if (!$process->isSuccessful()) {
			$output->writeln("Error in post ".$command." script occured.");
			$output->writeln($process->getErrorOutput());
		} else {
			$output->writeln($process->getOutput());
		}

		$output->writeln("========================");
		$output->writeln("End of post ". $command ." script");
		$output->writeln("========================");
	}
}
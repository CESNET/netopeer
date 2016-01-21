#!/bin/sh
if test "$1" = ""; then
	echo "Requires an argument - the path to \"cov-build\""
	exit 1
fi

./cov-configure.sh
$1 --dir cov-int ./cov-make.sh
tar czvf netopeer.tgz cov-int

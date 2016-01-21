#!/bin/sh
cd server
./configure --enable-tls
cd ../cli
./configure --enable-tls
cd ../transAPI/cfginterfaces
./configure
cd ../cfgsystem
./configure
cd ../turing
./configure
cd ../..

#!/bin/sh
cd server
make -B
cd ../cli
make -B
cd ../transAPI/cfginterfaces
make -B
cd ../cfgsystem
make -B
cd ../turing
make -B
cd ../..

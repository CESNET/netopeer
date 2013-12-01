#!/bin/bash
#
# nmp.sh : create process YIN/YANG data model for Netopeer GUI
# Copyright (C) 2012
# Author(s): Tomas Cejka  <cejkato2@fit.cvut.cz>
#
# LICENSE TERMS
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name of the Company nor the names of its contributors
#    may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# This software is provided ``as is'', and any express or implied
# warranties, including, but not limited to, the implied warranties of
# merchantability and fitness for a particular purpose are disclaimed.
# In no event shall the company or contributors be liable for any
# direct, indirect, incidental, special, exemplary, or consequential
# damages (including, but not limited to, procurement of substitute
# goods or services; loss of use, data, or profits; or business
# interruption) however caused and on any theory of liability, whether
# in contract, strict liability, or tort (including negligence or
# otherwise) arising in any way out of the use of this software, even
# if advised of the possibility of such damage.
#

OUTPUTDIR=""
CLEANDIR=0
DEBUG=0
NMPLOGFILE=/tmp/nmplogfile

help() {
  if [ $# -ne 1 ]; then
    echo "Usage: $0 [-c] [-d] -i <modelfile> -o <outputdir> -t <hostname> -p <port> -u <username>
    -c  cleanup outputdir
    -d  debug" > /dev/stderr
    exit 0
  fi
}

if [ "$#" -eq 0 ]; then
  help
  exit 0
fi

while getopts "?ho:i:cdt:p:u:" arg; do
  case $arg in
  "o") OUTPUTDIR=$OPTARG;;
  "i") INPUTFILE=$OPTARG;;
  "c") CLEANDIR=1;;
  "d") DEBUG=1;;
  "t") HOST=$OPTARG;;
  "p") PORT=$OPTARG;;
  "u") USERNAME=$OPTARG;;
  "?" | "h") help; ;;
  esac
done

if [ ! -f "$INPUTFILE" -o ! -r "$INPUTFILE" ]; then
  echo "Input file is not valid" 2> /dev/stderr
  exit 1
fi

if [ $DEBUG -eq 1 ]; then
  printf "output dir: %s\ninput file: %s\n" "$OUTPUTDIR" "$INPUTFILE"
  printf "clean output dir: %i\ndebug: %i\n" "$CLEANDIR" "$DEBUG"
fi


if [ ! -e "$INPUTFILE" ]; then
  echo "File $INPUTFILE does not exist" > /dev/stderr
  exit 1
fi

if [ ! -d "$OUTPUTDIR" ]; then
  echo "Directory $OUTPUTDIR does not exist" > /dev/stderr
  exit 1
fi
if [ ! -w "$OUTPUTDIR" ]; then
  echo "Cannot write into $OUTPUTDIR" > /dev/stderr
  exit 1
fi

if [ $CLEANDIR -eq 1 ]; then
  # clean up previous output
  rm -rf $OUTPUTDIR/*;
fi


file=`basename $INPUTFILE`
model=${file%.*}

#OUTPUTDIR="$OUTPUTDIR/$model"

mkdir -p $OUTPUTDIR

# generate RPC and model tree
echo "`date` "'pyang -f nmp --nmp-genidentifier --nmp-hostname "'$HOST'" --nmp-username "'$USERNAME'" --nmp-port "'$PORT'" --nmp-outputdir "'$OUTPUTDIR'" "'$INPUTFILE'"' >> "$NMPLOGFILE"

OUTPUT=$(pyang -f nmp --nmp-genidentifier --nmp-hostname "$HOST" --nmp-username "$USERNAME" --nmp-port "$PORT" --nmp-outputdir "$OUTPUTDIR" "$INPUTFILE")

IDENTIFIER=$(echo $OUTPUT | sed -n 's/.*Identifier:\s\([0-9a-zA-Z]*\).*/\1/p')
JSON=$(echo $OUTPUT | sed -n 's/.*JSON \({[^}]*}\).*/JSON \1/p')
MODELNAME=$(echo $JSON | sed -n 's/.*"module":\s*"\([^"]*\)".*/\1/p')
REVISION=$(echo $JSON | sed -n 's/.*"version":\s*"\([^"]*\)".*/\1/p')
echo $OUTPUT
echo "Generated identifier: $IDENTIFIER"
echo "$JSON"

echo "`date` $OUTPUT" >> "$NMPLOGFILE"
MODELDIR="$OUTPUTDIR/$IDENTIFIER/$MODELNAME/$REVISION"

if [ -e "$MODELDIR" ]; then
	echo "Already exists"
	echo "`date` Already exists ($MODELDIR)" >> "$NMPLOGFILE"
else
	mkdir -p "$MODELDIR"
	pyang -f nmp --nmp-genrpc  --nmp-outputdir "$MODELDIR" "$INPUTFILE" > /dev/null&
	#pyang -f nmp --nmp-genrpc  --nmp-outputdir "$MODELDIR" --nmp-hostname "$HOST" --nmp-username "$USERNAME" --nmp-port "$PORT" "$INPUTFILE" > /dev/null

	# generate wrapped form
	pyang -f wyin -o "$MODELDIR/wrapped.wyin" "$INPUTFILE" > /dev/null&

	# generate state information tree only
	pyang -f nmp --nmp-breaktree --nmp-genrpc --nmp-outputdir "$MODELDIR" "$INPUTFILE" > /dev/null&

	# generate config information tree only
	pyang -f nmp --nmp-breaktree --nmp-config --nmp-outputdir "$MODELDIR" "$INPUTFILE" > /dev/null&
	## get-config template
	#pyang -f resptempl --resptempl-config 1 $INPUTFILE > "$OUTPUTDIR/$model/resptempl"

	# create yin&yang model
        #pyang -f yin "$INPUTFILE" -o "$MODELDIR/$MODELNAME@$REVISION.yin" > /dev/null&
        #pyang -f yang "$INPUTFILE" -o "$MODELDIR/$MODELNAME@$REVISION.yang" > /dev/null&

	# Generating validation schemas
	# In the /usr/local/share/yang/xslt/ directory we expect *xsl files from pyang...
	# (basename.xsl, gen-relaxng.xsl)
	yang2dsdl  -d "$MODELDIR" "$INPUTFILE" > /dev/null&
	wait
	echo "`date` Generating of model finished." >> "$NMPLOGFILE"
fi

if [ $DEBUG -eq 1 ]; then
  tree $OUTPUTDIR
fi


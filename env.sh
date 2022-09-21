#!/bin/sh

# From: https://stackoverflow.com/a/20909045

## Usage:
##   . ./env.sh ; $COMMAND
##   . ./env.sh ; echo ${MINIENTREGA_FECHALIMITE}

unamestr=$(uname)
if [ "$unamestr" = 'Linux' ]; then

  export $(grep -v '^#' .env | xargs -d '\n')

elif [ "$unamestr" = 'FreeBSD' ] || [ "$unamestr" = 'Darwin' ]; then

  export $(grep -v '^#' .env | xargs -0)

fi


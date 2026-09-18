#!/bin/bash

FILE_NAME=${1}
cd /tests/
if [ -f test-${FILE_NAME}.sh ]; then
    bash test-${FILE_NAME}.sh
else
    echo "Couldn't find test-${FILE_NAME}.sh"
fi
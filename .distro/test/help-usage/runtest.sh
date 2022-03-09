#!/bin/sh

PACKAGE=sscg

# Assume the test will pass.
result=PASS

sscg --help | grep -q -i '^usage:'
if [ $? -ne 0 ]; then
        result=FAIL
fi

echo $result

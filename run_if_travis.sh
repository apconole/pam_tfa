#!/bin/bash

if [ "X$TRAVIS_JENKINS_RESULT" == "X" ]; then coveralls --gcov-options '\-lp'; fi

if [ "X$TRAVIS_JENKINS_RESULT" != "X" ]; then
    lcov --capture --base-directory . --directory . -o Results.lcov
    gcovr -r . -x -o code_coverage.xml
fi

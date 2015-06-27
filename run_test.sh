#!/bin/bash

PASSED=()
FAILED=()

TESTID=1

report(){
    # xunit xml
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone='yes'?>"
    echo "<TestRun>"
    echo "  <FailedTests>"
    OLDIFS=$IFS; IFS=','
    for FAILURE in "${FAILED[@]}"; do
        set $FAILURE
        echo "    <FailedTest id=\"$2\"><Name>$1</Name><FailureType>Assertion</FailureType><Message>assertion failed - Expected $3 but got $4</FailedTest>"
    done
    echo "  </FailedTests>"
    echo "  <SuccessfulTests>"
    for SUCCESS in "${PASSED[@]}"; do
        set $SUCCESS
        echo "    <Test id=\"$2\"><Name>$1</Name></Test>"
    done
    echo "  </SuccessfulTests>"
    IFS=$OLDIFS
    echo "</TestRun>"
}

testAssertFailure(){
    FAILED=("${FAILED[@]}" "${FUNCNAME[1]},$TESTID,to pass,forced fail")
}

testAssertPass(){
    PASSED=("${PASSED[@]}" "${FUNCNAME[1]},$TESTID,pass,pass")
}

testAssertEQ(){
    EXPECTED=$?
    if [ "$EXPECTED" == "$1" ]; then
        PASSED=("${PASSED[@]}" "${FUNCNAME[1]},$TESTID,$EXPECTED,$1")
    else
        FAILED=("${FAILED[@]}" "${FUNCNAME[1]},$TESTID,$EXPECTED,$1")
    fi
}

testAssertNEQ(){
    EXPECTED=$?
    if [ "$EXPECTED" != "$1" ]; then
        PASSED=("${PASSED[@]}" "${FUNCNAME[1]},$TESTID,$EXPECTED,$1")
    else
        FAILED=("${FAILED[@]}" "${FUNCNAME[1]},$TESTID,$EXPECTED,$1")
    fi
}

createTfaConfig(){
    cat > ~/.tfa_config <<EOF
email=foo@ahostthatdoesnotexistihope.com
from=foo@ahostthatdoesnotexistihope.com
server=ahostthatdoesnotexistihope.com
port=587
username=iamseriously
password=nothackingyou
fail=$1
EOF
    chmod go-rwx ~/.tfa_config
}

testTfaGOPerms(){
# setup
    createTfaConfig pass
    chmod go+r ~/.tfa_config
    
# run application
    echo "" | $TESTPAM $USER >/dev/null 2>/dev/null
    testAssertEQ 255

# teardown
    rm -f ~/.tfa_config
}

testNoTfaConfig(){
    rm -f ~/.tfa_config

# run
    echo "" | $TESTPAM $USER >/dev/null 2>/dev/null
    testAssertEQ 0

}

testTfaNoMail(){
# setup
    createTfaConfig deny
    
# run
    echo "" | $TESTPAM $USER >/dev/null 2>/dev/null
    testAssertEQ 255

# teardown
    rm -f ~/.tfa_config
}

testTfaTestAppConfig(){
    if [ ! -s /etc/pam.d/testtfa ]; then
        testAssertFailure
    else
        testAssertPass
    fi
}

if [ "X$TESTPAM" == "X" ]; then
TESTPAM=./testpam
fi

testTfaTestAppConfig
((TESTID++))
testTfaGOPerms
((TESTID++))
testNoTfaConfig
((TESTID++))
testTfaNoMail
((TESTID++))

report

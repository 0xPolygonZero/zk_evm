#!/bin/bash

# Args:
# 1 --> Expected measurement
# 2 --> New measurement

EXPECTED=$1
MEASUREMENT=$2

REGRESSION_PERCENT_THRESHOLD="${REGRESSION_PERCENT_THRESHOLD:-10}"

echo "Measured proving time is ${MEASUREMENT}, expected time ${EXPECTED}"

if (( $MEASUREMENT > $EXPECTED )); then
	REGRESSION_PERCENT=$(( (($MEASUREMENT-$EXPECTED)*100) / $EXPECTED ))
	if (( $REGRESSION_PERCENT > $REGRESSION_PERCENT_THRESHOLD )); then
		echo "Measured proving time has more than ${REGRESSION_PERCENT_THRESHOLD}% regression"
		exit 1
	fi
fi

echo "Measured proving is within expected tolerance"
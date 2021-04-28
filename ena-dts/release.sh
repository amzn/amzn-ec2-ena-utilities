#!/bin/bash

set -x
set -e

DEST_DIR="$(pwd)/dts-release"

rm -rf $DEST_DIR
mkdir -p $DEST_DIR

for dir in "conf" "dep" "output" "dep/patches" "tests" "test_plans"
do
	mkdir -p $DEST_DIR/$dir
done

cp README.md $DEST_DIR
cp RESULTS.md $DEST_DIR
cp LICENSE $DEST_DIR
cp THIRD_PARTY $DEST_DIR
cp VERSION $DEST_DIR

cd dts

for file in "framework" "nics" "test_plans" "tools" "dts" "dep/latency" \
	    "conf/test_case_checklist.json" "conf/test_case_supportlist.json" \
	    "conf/global_suite.cfg" "tests/TestSuite_ENA.py" \
	    "test_plans/ENA_test_plan.rst"
do
	cp -r $file $DEST_DIR/$file
done

DPDK_VERSIONS=( "v20_08" )
PKTGEN_VERSIONS=( "20_09_0" )

for ver in ${DPDK_VERSIONS[*]}; do
    cp -r "dep/patches/dpdk_${ver}" "${DEST_DIR}/dep/patches/"
    cp -r "dep/patches/latency_${ver}" "${DEST_DIR}/dep/patches/"
done

for ver in ${PKTGEN_VERSIONS[*]}; do
    cp -r "dep/patches/pktgen_${ver}" "${DEST_DIR}/dep/patches/"
done

cp execution.cfg_default $DEST_DIR/execution.cfg
cp conf/crbs.cfg_default $DEST_DIR/conf/crbs.cfg
cp conf/ports.cfg_default $DEST_DIR/conf/ports.cfg

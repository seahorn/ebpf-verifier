#!/bin/bash

### Update this path to the root of your prevail repository.
PREVAIL_ROOT=/Users/jorge/Repos/prevail-type-proofs


EBPF_BENCHMARKS=${PREVAIL_ROOT}/ebpf-samples
PREVAIL_CHECK=${PREVAIL_ROOT}/check
DOMAINS="zoneCrab"
PREFIX=prevail_$(date +"%m%d%y%H%M")

for dom in $DOMAINS
do
    rm -f log_${dom}.txt
    echo -n "Running Prevail with $dom ... "
    echo "File,Result,Cpu,Mem"  1>> ${PREFIX}_${dom}.csv
    for f in ${EBPF_BENCHMARKS}/*/*.o
    do
	sections=($(${PREVAIL_CHECK} $f -l 2> /dev/null))
	for s in "${sections[@]}"
	do
	    echo "${PREVAIL_CHECK} ${f} ${s} --domain=${dom}" >> log_${dom}.txt
	    echo -n $f:$s 1>> ${PREFIX}_${dom}.csv
	    o=$(${PREVAIL_CHECK} ${f} ${s} --domain=${dom} 2>>log_${dom}.txt)
	    echo -n ",$o" 1>> ${PREFIX}_${dom}.csv
	    echo 1>> ${PREFIX}_${dom}.csv
	done
    done
    echo "DONE"
done

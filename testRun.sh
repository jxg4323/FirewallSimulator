#!/bin/bash +x 
#
# offer choices to run firewall. 
# modify this script to do testing.

IPATH=$HOME/pub/projects/Firewall
OPATH=./OutData
SOLUTION=./referenceFirewall

if [ ! -p ToFirewall ]; then
    mkfifo ToFirewall
fi

if [ ! -p FromFirewall ]; then
    mkfifo FromFirewall
fi

VGRIND0="valgrind --leak-check=full "
VGRIND1="valgrind --leak-check=full --show-leak-kinds=all "
VGRIND2="valgrind --leak-check=full --suppressions=valgrind.supp "
VGRIND3="valgrind --leak-check=full --show-leak-kinds=all --suppressions=valgrind.supp "
VGRIND4="valgrind --leak-check=full --show-leak-kinds=all --suppressions=valgrind.supp --gen-suppressions=all "
VGRIND5="valgrind --leak-check=full --show-leak-kinds=all --suppressions=valgrind.supp -v "

# Test Choices Array
#
declare -a tstid=(
'fwSim' 
"fwSim -i packets.3 -o ${OPATH} -d 20 -- $SOLUTION config1.txt "
"fwSim -i packets.3 -o ${OPATH} -d 20 -- $VGRIND2 $SOLUTION config1.txt "
"fwSim -i packets.3 -o ${OPATH} -d 20 -- $VGRIND0 ./firewall config1.txt "
# add further choices for your test suite
) 

# echo ${tstid[@]}
#
# runner function
#

runtest() {
    # capture program output to OutText while watching its progress.
    echo ""
    echo "====== Number $1"
    echo ${tstid[${1}]} |tee OutText
    ${tstid[${1}]} 2>&1 |tee -a OutText
    echo "======"
}

num=0

#
# menu
#
echo "Test Choices:"
while :
do
    if [ ${num} -eq ${#tstid[@]} ]; then
        break
    fi
    echo ${num} : ${tstid[${num}]}
    echo ""
    num=`expr ${num} + 1`
done

#
# handle choice from command line or menu
#
if [ $# -ne 0 ]; then

    runtest $1
else
    read -p "Choice: " choice
    runtest ${choice}
fi

exit $?


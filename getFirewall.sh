#!/bin/sh
# install links and copies for students

echo installing supplied binaries and program starter files

PUBPATH=/home/course/csci243/pub/projects/Firewall

# starter sources, objects and build stuff
cp -p ${PUBPATH}/*.sh  .
chmod +x *.sh
cp -p ${PUBPATH}/*.c  .
ln -s ${PUBPATH}/*.o  .
cp -p ${PUBPATH}/*.h  .
cp -p ${PUBPATH}/header.mak .

# binaries (link)
ln -s ${PUBPATH}/fwSim  .
ln -s ${PUBPATH}/pktAnalyzer  .
ln -s ${PUBPATH}/referenceFirewall  .

# data (link)
ln -s ${PUBPATH}/packets.1  .
ln -s ${PUBPATH}/packets.3  .

# config and test files
cp -p ${PUBPATH}/config*.txt   .
cp -p ${PUBPATH}/script1.txt   .
cp -p ${PUBPATH}/valgrind.supp .


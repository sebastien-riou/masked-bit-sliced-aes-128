#!/bin/sh

baseDir=.
testDir=$baseDir/test
sourceDir=$baseDir/source
includeDir=$baseDir/include

if [ -z ${CXX+x} ]; then CXX=c++; fi

$CXX -Ofast -std=c++11 $testDir/main.cpp $sourceDir/bitslice.c $sourceDir/secure_aes_pbs.c -I $includeDir -o masked-bit-sliced-aes-128 $*


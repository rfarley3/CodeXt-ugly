#! /bin/sh

#ls *cd80* |grep 1024kb | sort | head -1
#ls *cd80* |grep 10240kb | sort | head -1
#ls *cd80* |grep 102400kb | sort | head -1


cp ObfuscationTesting/randfill/firstRan-1.sh firstRan.sh
make run
cp s2e-last/debug.txt ObfuscationTesting/randfill/1-debug.txt

cp ObfuscationTesting/randfill/firstRan-2.sh firstRan.sh
make run
cp s2e-last/debug.txt ObfuscationTesting/randfill/2-debug.txt

cp ObfuscationTesting/randfill/firstRan-3.sh firstRan.sh
make run
cp s2e-last/debug.txt ObfuscationTesting/randfill/3-debug.txt
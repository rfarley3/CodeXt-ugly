#! /bin/bash

x=1
while [ $x -eq 1 ]
do
	echo "Server started"
	nc -l 10000 -vvv
	echo "Server killed"
done

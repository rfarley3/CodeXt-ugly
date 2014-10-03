#!/bin/sh
# convert-sc.sh
objdump -d $1 | awk -F '\t' '{printf $2}' | \
	awk 'BEGIN { cnt=0; print; printf "unsigned char buf[]=\n\""}
	     {
		x=0;
		while(x<NF){
			if(x % 15 == 0 && x !=0){ printf "\"\n\""}
			printf "\\x"$(x+1); x++; cnt++
		}
		print "\";\n\nLength: "cnt
	      }'

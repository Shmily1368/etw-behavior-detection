#!/bin/bash

for line in `cat timestamp`
do
	grep $line 2019-06-26-10-25-34.out > /dev/null
	if [ $? -eq 1 ];then
		echo $? $line
	fi
done

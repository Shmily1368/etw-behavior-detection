#! /bin/bash

# echo "Hello"
info=$(supervisorctl status | grep detector-srv)
pid=${info##*pid}
# echo ${pid}
t=${pid%%,*}
echo ${t}
echo "generate the raw file: a.out"
top -b -n 1 | grep %CPU >> a.out 2>/dev/null
sleep 2s
# while true
# do
top -b -p ${t} > a.out 2>/dev/null
# sleep 2s
# done


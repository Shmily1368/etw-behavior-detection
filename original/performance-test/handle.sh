#! /bin/bash

# echo "Hello"
echo "generate the handle file: b.out"
top -b -n 1 | grep %CPU > b.out 2>/dev/null
sleep 2s
str="root"
cat a.out | while read line
do
if [[ $line =~ $str ]]
then
echo $line >> b.out
fi
# echo $line
# echo "========================================="
done


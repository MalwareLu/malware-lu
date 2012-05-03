#!/bin/bash

if [ $# -ne 1 ]
then
	echo "Usage: `basename $0` {virus_folder}"
	exit 1
fi

success=0
total=0

files=$(yara yara.rules $1 | awk '{print $2}')

for f in $files
do
	./unpacker-v3 $f
	if [ $? -eq 0 ]
	then
		success=$((success+1))
	else
		failed[${#failed[*]}]=$f
	fi
	total=$((total+1))
	echo "---------------------------------------------"
done

echo "Success $success/$total"
if [ $success -ne $total ]
then
	echo "---------------------------------------------"
	echo "File failed:"
	for f in "${failed[@]}"
	do
		echo $f
	done
fi


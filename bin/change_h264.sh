#!/bin/bash

if [[ $1 -eq 1 ]]
then
file_name="bus_cavlc/bus_cavlc"
elif  [[ $1 -eq 2 ]]
then
file_name="sumsung_cabac/sumsung_720p_50M"
elif [[ $1 -eq 3 ]]
then
file_name="bus_cabac/bus_cabac"
fi

echo $file_name

raw_h264_file=${file_name}"_Copy.264"
new_h264_file=${file_name}".264"

v_dir="./vfile"

rm -f ${raw_h264_file}".key.txt" || exit
echo "delete : "${raw_h264_file}".key.txt"

rm -f ${v_dir}"/"${new_h264_file}
cp ${v_dir}"/"${raw_h264_file} ${v_dir}"/"${new_h264_file}

echo "cp "${raw_h264_file}" to "${new_h264_file}

#!/bin/bash
snort="/home/ubuntu/Desktop/snort.log"
touch "$snort"
while true; do

snort -c /etc/snort/snort.lua -i br0 -q >> "$snort"

done

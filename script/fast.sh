#!/bin/bash

# Copyright (c) 2026 Hamad hossen hamad Al-Warfali
# Licensed under the MIT License.

snort="/home/ubuntu/Desktop/snort.log"
touch "$snort"
while true; do

snort -c /etc/snort/snort.lua -i br0 -q >> "$snort"

done

#!/bin/bash
set -e # Exit on error
nft -f /app/ruleset.txt 
nft list ruleset 
tcpdump -i eth0 -n -s 0 -w /app/pcap.pcap &
/app/brstack &
while true; do # for debugging
    sleep 1
done

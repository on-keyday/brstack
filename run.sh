#!/bin/bash
set -e # Exit on error
nft -f /app/ruleset.txt 
nft list ruleset 
/app/brstack
while true; do # for debugging
    sleep 1
done

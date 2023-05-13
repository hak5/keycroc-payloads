#!/usr/bin/env python
import os, time

ctr = 0
while True:
    ctr += 1
    os.system("WAIT_FOR_KEYBOARD_INACTIVITY > /dev/null 2>&1")
    print "Sending SHIFT keypress for the " + str(ctr) + ". time!"
    os.system("QUACK SHIFT")
    time.sleep(50)


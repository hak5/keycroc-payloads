#!/bin/bash

function quackWindows() {

        # open normal powershell (non admin)
        Q GUI r
        Q DELAY 500
        Q STRING powershell
        Q ENTER
        Q DELAY 500

        # get drive
	# provides helpful variable that can be used to write data to the UMS
        Q STRING '$usbPath = Get-WMIObject Win32_Volume | ? { $_.Label -eq'
        Q STRING " 'sneaky'"
        Q STRING ' } | select -expand name'
        Q ENTER

	############################
	# ADD YOUR COMMANDS HERE
	############################

        # write done file and clear write cache
	# done file is only needed if set inside the pyload.sh
	# e.g. for this case doneFile is set to "done.txt"
	# and therefore the file will be created
        Q STRING '[IO.File]::WriteAllLines((Join-Path $usbPath'
        Q STRING " 'done.txt'), 'done') ; Write-VolumeCache"
        Q STRING ' $usbPath[0] ; exit'
        Q ENTER
}

function quackLinux() {

        # open terminal via search menu
        Q GUI
        Q DELAY 1500
        Q STRING "ter"
        # needed otherwise console might bug
        Q DELAY 500
        Q ENTER
        Q DELAY 2000

        ############################
        # ADD YOUR COMMANDS HERE
        ############################

        # write done file and clear write cache
        # done file is only needed if set inside the pyload.sh
        # e.g. for this case doneFile is set to "done.txt"
        # and therefore the file will be created
        Q STRING "echo 'done' > /media/"
        Q STRING '$(users)/sneaky/done.txt && sync && exit'
        Q ENTER
}

function quackMac() {

        # open mac terminal
        Q GUI SPACE
        Q DELAY 3000
        Q STRING "termi"
        Q DELAY 500
        Q ENTER
        Q DELAY 3000

        ############################
        # ADD YOUR COMMANDS HERE
        ############################

        # write done file and clear write cache
        # done file is only needed if set inside the pyload.sh
        # e.g. for this case doneFile is set to "done.txt"
        # and therefore the file will be created
        Q STRING "echo 'done' > /Volumes/sneaky/done.txt"
        Q STRING " && sync && pkill -a Terminal"
        Q ENTER
}

case $1 in

  Windows)
    quackWindows
    ;;

  Linux)
    quackLinux
    ;;

  Mac)
    quackMac
    ;;

esac

